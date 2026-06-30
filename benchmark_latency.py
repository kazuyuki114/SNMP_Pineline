"""
benchmark_latency.py
────────────────────
Đo latency của pipeline TS2Vec inference real-time.

Mô phỏng cách hoạt động thực tế:
  - Dữ liệu SNMP đến từng timestamp một (nhiều device/timestamp)
  - Duy trì sliding buffer T=10 timestep đã preprocess
  - Mỗi khi buffer đầy → chạy inference
  - Đo latency từng bước: preprocess | embed | score | total

Usage:
    python benchmark_latency.py --input attack_snmp_port_scan_1.csv
    python benchmark_latency.py --input snmp_labeled_final.csv --warmup 20 --runs 200
"""

import argparse
import os
import pickle
import time
from collections import deque

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
import torch.nn as nn


# ── Model (phải khớp training) ────────────────────────────────────────────────
class DilatedBlock(nn.Module):
    def __init__(self, ch, dilation):
        super().__init__()
        self.conv = nn.Conv1d(ch, ch, kernel_size=3, padding=dilation, dilation=dilation)
        self.norm = nn.GroupNorm(1, ch)
        self.act  = nn.GELU()

    def forward(self, x):
        return x + self.act(self.norm(self.conv(x)))


class TS2VecEncoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, embed_dim, depth=4):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.blocks = nn.ModuleList([DilatedBlock(hidden_dim, 2**i) for i in range(depth)])
        self.proj   = nn.Linear(hidden_dim, embed_dim)

    def forward(self, x):
        h = self.input_proj(x)
        h = h.permute(0, 2, 1)
        for blk in self.blocks:
            h = blk(h)
        return self.proj(h.mean(-1))


# ── Realtime Buffer ───────────────────────────────────────────────────────────
NON_COLS = ['Timestamp', 'Device', 'IP', 'label', 'label_id']


class RealtimeBuffer:
    """
    Nhận từng nhóm rows (1 timestamp, nhiều device) → preprocess → push vào buffer.
    Khi buffer đủ T=10 → trả về window (T, F) sẵn sàng inference.
    """
    def __init__(self, scaler, feature_cols, T=10):
        self.scaler       = scaler
        self.feature_cols = feature_cols
        self.T            = T
        self.cnt_cols     = None
        self.prev_vals    = {}
        self.buffer       = deque(maxlen=T)

    def push(self, group_df):
        if self.cnt_cols is None:
            self.cnt_cols = [c for c in group_df.columns if c not in NON_COLS]

        # --- delta per device ---
        delta_rows = {}
        for _, row in group_df.iterrows():
            dev  = row['Device']
            curr = row[self.cnt_cols].values.astype(np.float32)
            if dev in self.prev_vals:
                delta = curr - self.prev_vals[dev]
                if (delta >= 0).all():
                    delta_rows[dev] = delta
            self.prev_vals[dev] = curr

        if not delta_rows:
            return None

        # --- pivot: device__metric → value ---
        pivoted = {}
        for dev, delta in delta_rows.items():
            for col, val in zip(self.cnt_cols, delta):
                pivoted[f'{dev}__{col}'] = val

        # --- align với feature_cols ---
        vec = np.array([pivoted.get(c, 0.0) for c in self.feature_cols],
                       dtype=np.float32).reshape(1, -1)

        # --- scale ---
        vec_scaled = self.scaler.transform(vec)[0]

        # --- push vào buffer ---
        self.buffer.append(vec_scaled)

        if len(self.buffer) == self.T:
            return np.stack(list(self.buffer), axis=0)   # (T, F)
        return None


# ── Load artifacts ────────────────────────────────────────────────────────────
def load_artifacts(meta_path, encoder_path, detector_path, device):
    with open(meta_path, 'rb') as f:
        meta = pickle.load(f)
    with open(detector_path, 'rb') as f:
        det_art = pickle.load(f)

    cfg     = meta['cfg']
    encoder = TS2VecEncoder(cfg['input_dim'], cfg['hidden_dim'],
                            cfg['embed_dim'], cfg['depth'])
    encoder.load_state_dict(torch.load(encoder_path, map_location=device))
    encoder.to(device).eval()

    # Detect detector type by keys present
    det_art['_type'] = 'gmm' if 'gmm' in det_art else 'mahal'
    return encoder, meta, det_art


# ── Single-window inference ───────────────────────────────────────────────────
@torch.no_grad()
def infer_one(window_np, encoder, det_art, device):
    t0 = time.perf_counter()

    x = torch.tensor(window_np[np.newaxis], dtype=torch.float32).to(device)
    h = encoder(x).cpu().numpy().astype(np.float64)
    t_embed = time.perf_counter() - t0

    t1 = time.perf_counter()
    if det_art['_type'] == 'gmm':
        score = -det_art['gmm'].score_samples(h)[0]
    else:
        diff  = h - det_art['centroid']
        score = float(np.sqrt(np.clip((diff @ det_art['inv_cov'] * diff).sum(axis=1), 0, None))[0])
    t_score = time.perf_counter() - t1

    label = int(score > det_art['threshold_pct'])
    return score, label, t_embed, t_score


# ── Benchmark ─────────────────────────────────────────────────────────────────
def run_benchmark(df_raw, encoder, meta, det_art, device, warmup=10, max_runs=None):
    scaler       = meta['scaler']
    feature_cols = meta['feature_cols']
    T            = meta['cfg']['timesteps']

    buf = RealtimeBuffer(scaler, feature_cols, T)

    timestamps = df_raw['Timestamp'].sort_values().unique()

    lat_preprocess, lat_embed, lat_score, lat_total = [], [], [], []
    results = []
    infer_count = 0

    for ts in timestamps:
        group = df_raw[df_raw['Timestamp'] == ts]

        t_pre_start = time.perf_counter()
        window = buf.push(group)
        t_pre = time.perf_counter() - t_pre_start

        if window is None:
            continue

        t_total_start = time.perf_counter()
        score, label, t_embed, t_score_step = infer_one(window, encoder, det_art, device)
        t_total = (time.perf_counter() - t_total_start) + t_pre

        infer_count += 1
        if infer_count <= warmup:
            continue

        lat_preprocess.append(t_pre * 1000)
        lat_embed.append(t_embed * 1000)
        lat_score.append(t_score_step * 1000)
        lat_total.append(t_total * 1000)
        results.append({'timestamp': ts, 'score': score, 'label': label})

        if max_runs and len(lat_total) >= max_runs:
            break

    return (np.array(lat_preprocess), np.array(lat_embed),
            np.array(lat_score),      np.array(lat_total),
            pd.DataFrame(results))


def stats_dict(arr):
    return {
        'mean': arr.mean(), 'p50': np.percentile(arr, 50),
        'p95':  np.percentile(arr, 95), 'p99': np.percentile(arr, 99),
        'min':  arr.min(), 'max': arr.max(), 'std': arr.std(),
    }


def print_stats(name, arr, unit='ms'):
    if len(arr) == 0:
        print(f"  {name}: no data")
        return
    s = stats_dict(arr)
    print(f"  {name:<12}  "
          f"mean={s['mean']:.3f}{unit}  "
          f"p50={s['p50']:.3f}{unit}  "
          f"p95={s['p95']:.3f}{unit}  "
          f"p99={s['p99']:.3f}{unit}  "
          f"min={s['min']:.3f}{unit}  "
          f"max={s['max']:.3f}{unit}")


def save_results(out_dir, input_name, detector_tag, lat_pre, lat_embed, lat_score,
                 lat_total, results, det_art, meta):
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(input_name))[0] + f'_{detector_tag}'

    score_label = 'mahal_ms' if det_art['_type'] == 'mahal' else 'gmm_score_ms'
    lat_df = pd.DataFrame({
        'preprocess_ms': lat_pre,
        'embed_ms':      lat_embed,
        score_label:     lat_score,
        'total_ms':      lat_total,
    })
    lat_csv = os.path.join(out_dir, f'{stem}_latency_raw.csv')
    lat_df.to_csv(lat_csv, index=False)

    rows = []
    for name, arr in [('preprocess', lat_pre), ('embed', lat_embed),
                      (score_label.replace('_ms', ''), lat_score), ('total', lat_total)]:
        s = stats_dict(arr)
        s['stage'] = name
        rows.append(s)
    summary_df = pd.DataFrame(rows).set_index('stage')
    sum_csv = os.path.join(out_dir, f'{stem}_latency_summary.csv')
    summary_df.to_csv(sum_csv)

    res_csv = os.path.join(out_dir, f'{stem}_predictions.csv')
    results.to_csv(res_csv, index=False)

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    ax = axes[0]
    ax.plot(lat_total, label='total',      color='steelblue', lw=1.2, alpha=0.8)
    ax.plot(lat_embed, label='embed',      color='orange',    lw=1,   alpha=0.7)
    ax.plot(lat_pre,   label='preprocess', color='green',     lw=1,   alpha=0.7)
    ax.axhline(np.mean(lat_total), color='steelblue', linestyle='--', lw=1,
               label=f'mean={np.mean(lat_total):.2f}ms')
    ax.set_xlabel('Inference #'); ax.set_ylabel('Latency (ms)')
    ax.set_title('Latency over time'); ax.legend(fontsize=8); ax.grid(alpha=0.3)

    ax = axes[1]
    ax.hist(lat_total, bins=30, color='steelblue', edgecolor='white', alpha=0.85)
    for pct, ls, lbl in [(50,'--','p50'), (95,'-.','p95'), (99,':','p99')]:
        v = np.percentile(lat_total, pct)
        ax.axvline(v, linestyle=ls, color='crimson', lw=1.5, label=f'{lbl}={v:.2f}ms')
    ax.set_xlabel('Total latency (ms)'); ax.set_ylabel('Count')
    ax.set_title('Latency Distribution'); ax.legend(fontsize=8); ax.grid(alpha=0.3)

    ax = axes[2]
    ax.boxplot([lat_pre, lat_embed, lat_score, lat_total],
               tick_labels=['preprocess', 'embed', detector_tag.split('-')[0], 'total'],
               patch_artist=True,
               boxprops=dict(facecolor='#cce5ff', color='steelblue'),
               medianprops=dict(color='crimson', lw=2))
    ax.set_ylabel('Latency (ms)'); ax.set_title('Stage Breakdown'); ax.grid(alpha=0.3, axis='y')

    thr = det_art['threshold_pct']
    n   = len(lat_total)
    n_a = int(results['label'].sum())
    T   = meta['cfg']['timesteps']
    plt.suptitle(
        f'TS2Vec Real-time Benchmark [{detector_tag}] — {os.path.basename(input_name)}\n'
        f'{n} inferences | {n_a} anomaly / {n-n_a} normal | '
        f'Threshold={thr:.4f} | T={T}',
        fontsize=11
    )
    fig.tight_layout()
    plot_path = os.path.join(out_dir, f'{stem}_latency_plot.png')
    fig.savefig(plot_path, dpi=130, bbox_inches='tight')
    plt.close(fig)

    print(f"\nSaved:")
    print(f"  {lat_csv}")
    print(f"  {sum_csv}")
    print(f"  {res_csv}")
    print(f"  {plot_path}")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TS2Vec real-time inference latency benchmark')
    parser.add_argument('--input',      required=True)
    parser.add_argument('--meta',       default='ts2vec_pipeline_meta.pkl')
    parser.add_argument('--encoder',    default='encoder_ts2vec.pt')
    parser.add_argument('--detector',   default='mahal_detector_ts2vec.pkl',
                        help='Path to detector pkl (GMM or Mahalanobis)')
    parser.add_argument('--device',     default='cuda' if torch.cuda.is_available() else 'cpu')
    parser.add_argument('--warmup',     type=int, default=10)
    parser.add_argument('--runs',       type=int, default=None)
    parser.add_argument('--out-dir',    default='benchmark_results')
    args = parser.parse_args()

    device = torch.device(args.device)
    print(f"Device   : {device}")
    print(f"Loading artifacts...")
    encoder, meta, det_art = load_artifacts(args.meta, args.encoder, args.detector, device)

    det_type = det_art['_type'].upper()
    detector_tag = f'{"Mahal" if det_type == "MAHAL" else "GMM5"}-96pct'
    print(f"Detector : {det_type}  |  Threshold (96pct): {det_art['threshold_pct']:.4f}")

    df_raw = pd.read_csv(args.input, parse_dates=['Timestamp'])
    print(f"Input    : {args.input}  ({len(df_raw)} rows, "
          f"{df_raw['Timestamp'].nunique()} timestamps)")
    print(f"Warmup   : {args.warmup} inferences (excluded from stats)\n")

    (lat_pre, lat_embed, lat_score, lat_total,
     results) = run_benchmark(df_raw, encoder, meta, det_art, device,
                              warmup=args.warmup, max_runs=args.runs)

    n = len(lat_total)
    if n == 0:
        print("Không đủ dữ liệu để benchmark (cần ít nhất T+warmup timestamps).")
    else:
        n_anomaly = results['label'].sum()
        score_stage = 'mahal dist' if det_type == 'MAHAL' else 'gmm score'
        print(f"{'='*70}")
        print(f"Benchmark Results  [{detector_tag}]  ({n} inferences, "
              f"{n_anomaly} anomaly / {n-n_anomaly} normal)")
        print(f"{'='*70}")
        print_stats("preprocess", lat_pre)
        print_stats("embed",      lat_embed)
        print_stats(score_stage,  lat_score)
        print_stats("TOTAL",      lat_total)
        print(f"{'='*70}")
        print(f"\nThroughput: {1000/lat_total.mean():.1f} inferences/sec  "
              f"(= {1000/lat_total.mean()*meta['cfg']['timesteps']*15:.0f} SNMP-sec/sec)")

        print(f"\nSample results (first 5):")
        print(results.head(5).to_string(index=False))

        save_results(args.out_dir, args.input, detector_tag,
                     lat_pre, lat_embed, lat_score, lat_total,
                     results, det_art, meta)
