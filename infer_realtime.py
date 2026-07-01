#!/usr/bin/env python3
"""
infer_realtime.py
-----------------
Liên tục đọc dữ liệu mới nhất từ snmp.snmp_labeled_final mỗi 15s,
chạy TS2Vec inference, đẩy kết quả vào snmp.anomaly_results.

Startup: warm-up buffer bằng T+1 timestamps gần nhất từ ClickHouse.
Loop:    mỗi 15s phát hiện timestamp mới → push buffer → infer → insert.

Usage:
    python infer_realtime.py
"""

import base64
import csv
import http.client
import io
import os
import pickle
import sys
import time
from collections import deque
from datetime import datetime
from urllib.parse import urlencode

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

INTERVAL = 15  # giây

CLICKHOUSE_HOST = ""
CLICKHOUSE_HTTP_PORT = 443
CLICKHOUSE_BASE_PATH = "/clickhouse"
CLICKHOUSE_SECURE = True
CLICKHOUSE_USER = ""
CLICKHOUSE_PASSWORD = ""


class ClickHouseHTTP:
    def __init__(self, host, port, user, password, secure=False, timeout=30, base_path=""):
        connection_cls = http.client.HTTPSConnection if secure else http.client.HTTPConnection
        self.conn = connection_cls(host, port, timeout=timeout)
        self.base_path = base_path.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        self.base_headers = {"Authorization": f"Basic {token}"}

    def query(self, sql, body=None, content_type="text/plain; charset=utf-8"):
        headers = dict(self.base_headers)
        headers["Content-Type"] = content_type
        path = self.base_path + "/?" + urlencode({"query": sql})
        self.conn.request("POST", path, body=body, headers=headers)
        response = self.conn.getresponse()
        response_body = response.read().decode("utf-8", errors="replace")
        if response.status >= 300:
            raise RuntimeError(f"ClickHouse HTTP {response.status}: {response_body}")
        return response_body

    def close(self):
        self.conn.close()

# ---------------------------------------------------------------------------
# Model (khớp với training)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Realtime Buffer (giữ nguyên từ benchmark_latency.py)
# ---------------------------------------------------------------------------

NON_COLS = ['Timestamp', 'Device', 'IP', 'label', 'label_id']


class RealtimeBuffer:
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

        pivoted = {}
        for dev, delta in delta_rows.items():
            for col, val in zip(self.cnt_cols, delta):
                pivoted[f'{dev}__{col}'] = val

        vec = np.array([pivoted.get(c, 0.0) for c in self.feature_cols],
                       dtype=np.float32).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)[0]
        self.buffer.append(vec_scaled)

        if len(self.buffer) == self.T:
            return np.stack(list(self.buffer), axis=0)  # (T, F)
        return None


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def load_artifacts(artifact_dir, torch_device):
    paths = {
        'meta':     os.path.join(artifact_dir, 'ts2vec_pipeline_meta.pkl'),
        'encoder':  os.path.join(artifact_dir, 'encoder_ts2vec.pt'),
        'detector': os.path.join(artifact_dir, 'mahal_detector_ts2vec.pkl'),
    }
    for name, p in paths.items():
        if not os.path.exists(p):
            raise FileNotFoundError(f"Artifact '{name}' not found: {p}")

    with open(paths['meta'], 'rb') as f:
        meta = pickle.load(f)
    with open(paths['detector'], 'rb') as f:
        det_art = pickle.load(f)

    cfg = meta['cfg']
    encoder = TS2VecEncoder(cfg['input_dim'], cfg['hidden_dim'],
                            cfg['embed_dim'], cfg['depth'])
    encoder.load_state_dict(torch.load(paths['encoder'], map_location=torch_device))
    encoder.to(torch_device).eval()

    det_art['_type'] = 'gmm' if 'gmm' in det_art else 'mahal'
    if THRESHOLD_OVERRIDE is not None:
        det_art['threshold_pct'] = float(THRESHOLD_OVERRIDE)
    return encoder, meta, det_art


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

@torch.no_grad()
def infer_one(window_np, encoder, det_art, torch_device):
    x = torch.tensor(window_np[np.newaxis], dtype=torch.float32).to(torch_device)
    h = encoder(x).cpu().numpy().astype(np.float64)

    if det_art['_type'] == 'gmm':
        score = float(-det_art['gmm'].score_samples(h)[0])
    else:
        diff  = h - det_art['centroid']
        score = float(np.sqrt(
            np.clip((diff @ det_art['inv_cov'] * diff).sum(axis=1), 0, None)
        )[0])

    is_anomaly = int(score > det_art['threshold_pct'])
    return score, is_anomaly


# ---------------------------------------------------------------------------
# ClickHouse helpers
# ---------------------------------------------------------------------------

def make_client(host, port, user, pwd, base_path, secure):
    return ClickHouseHTTP(host, port, user, pwd,
                          secure=secure, base_path=base_path, timeout=30)


def query_df(client, sql):
    """Chạy SELECT query → trả về DataFrame. Tự thêm FORMAT CSVWithNames."""
    full_sql = sql.rstrip().rstrip(';') + '\nFORMAT CSVWithNames'
    resp = client.query(full_sql)
    if not resp or not resp.strip():
        return pd.DataFrame()
    return pd.read_csv(io.StringIO(resp))


def insert_anomaly_results(client, rows):
    """rows: list of dict {Timestamp, score, is_anomaly, detector_type, threshold}"""
    if not rows:
        return
    columns = ['Timestamp', 'score', 'is_anomaly', 'detector_type', 'threshold']
    buf     = io.StringIO()
    writer  = csv.DictWriter(buf, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    sql = (
        "INSERT INTO `snmp`.`anomaly_results` "
        "(`Timestamp`, `score`, `is_anomaly`, `detector_type`, `threshold`) "
        "FORMAT CSVWithNames"
    )
    client.query(sql, body=buf.getvalue().encode('utf-8'), content_type='text/csv')


# ---------------------------------------------------------------------------
# Fetch data từ ClickHouse
# ---------------------------------------------------------------------------

def fetch_warmup(client, T):
    """
    Lấy T+1 timestamps gần nhất từ snmp_labeled_final để warm-up buffer.
    T+1 timestamps → T delta steps → lần push cuối trả về window đầu tiên.
    """
    sql = f"""
    SELECT *
    FROM snmp.snmp_labeled_final
    WHERE Timestamp IN (
        SELECT DISTINCT Timestamp
        FROM snmp.snmp_labeled_final
        ORDER BY Timestamp DESC
        LIMIT {T + 1}
    )
    ORDER BY Timestamp ASC, Device ASC
    """
    df = query_df(client, sql)
    if not df.empty and 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    return df


def fetch_since(client, after_ts):
    """Lấy tất cả timestamps > after_ts, sắp xếp tăng dần."""
    ts_str = pd.Timestamp(after_ts).strftime('%Y-%m-%d %H:%M:%S')
    sql = f"""
    SELECT *
    FROM snmp.snmp_labeled_final
    WHERE Timestamp > '{ts_str}'
    ORDER BY Timestamp ASC, Device ASC
    """
    df = query_df(client, sql)
    if not df.empty and 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    return df


def fetch_latest_ts(client):
    """Lấy timestamp mới nhất trong bảng."""
    df = query_df(client, "SELECT max(Timestamp) AS ts FROM snmp.snmp_labeled_final")
    if df.empty or df['ts'].iloc[0] is None:
        return None
    return pd.Timestamp(df['ts'].iloc[0])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ARTIFACT_DIR       = 'artifact'
TORCH_DEVICE       = 'cuda' if torch.cuda.is_available() else 'cpu'
THRESHOLD_OVERRIDE = 17.0   # đặt None để dùng threshold gốc từ artifact


def main():
    torch_device = torch.device(TORCH_DEVICE)

    # --- Load artifacts ---
    print(f"[1/3] Loading artifacts from '{ARTIFACT_DIR}' ...")
    encoder, meta, det_art = load_artifacts(ARTIFACT_DIR, torch_device)
    T            = meta['cfg']['timesteps']   # 10
    feature_cols = meta['feature_cols']       # 232 cols
    scaler       = meta['scaler']
    det_type     = det_art['_type']
    threshold    = float(det_art['threshold_pct'])
    print(f"      T={T}, input_dim={meta['cfg']['input_dim']}, "
          f"detector={det_type}, threshold={threshold:.4f}")

    # --- ClickHouse client ---
    print(f"      ClickHouse: {CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT}{CLICKHOUSE_BASE_PATH}")
    client = make_client(CLICKHOUSE_HOST, CLICKHOUSE_HTTP_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD,
                         CLICKHOUSE_BASE_PATH, CLICKHOUSE_SECURE)

    # --- Warm-up buffer ---
    print(f"\n[2/3] Warm-up: fetching last {T+1} timestamps from snmp_labeled_final ...")
    buf      = RealtimeBuffer(scaler, feature_cols, T)
    last_ts  = None
    warmup_inferences = 0

    try:
        warmup_df = fetch_warmup(client, T)
    except Exception as e:
        print(f"      [ERROR] Warm-up query failed: {e}", file=sys.stderr)
        sys.exit(1)

    if warmup_df.empty:
        print("      [WARN] Bảng snmp_labeled_final chưa có dữ liệu. "
              "Bắt đầu vòng lặp và chờ dữ liệu mới...")
    else:
        warmup_timestamps = sorted(warmup_df['Timestamp'].unique())
        print(f"      Got {len(warmup_timestamps)} timestamps × "
              f"{warmup_df['Device'].nunique()} devices = {len(warmup_df)} rows")

        for ts in warmup_timestamps:
            group  = warmup_df[warmup_df['Timestamp'] == ts].copy()
            window = buf.push(group)
            if window is not None:
                score, is_anomaly = infer_one(window, encoder, det_art, torch_device)
                warmup_inferences += 1
            last_ts = ts

        print(f"      Buffer warmed up. Inferences during warm-up: {warmup_inferences}")
        if last_ts is not None:
            print(f"      Last seen timestamp: {last_ts}")

    # --- Continuous loop ---
    print(f"\n[3/3] Starting continuous inference loop (interval={INTERVAL}s) ...")
    print(f"      Press Ctrl+C to stop.\n")

    try:
        while True:
            loop_start = time.time()
            now_str    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            try:
                # Nếu chưa có last_ts, lấy latest timestamp hiện tại làm mốc
                if last_ts is None:
                    last_ts = fetch_latest_ts(client)
                    if last_ts is None:
                        print(f"[{now_str}] Bảng rỗng, chờ dữ liệu...", flush=True)
                        time.sleep(INTERVAL)
                        continue

                # Lấy các rows mới hơn last_ts
                new_df = fetch_since(client, last_ts)

                if new_df.empty:
                    print(f"[{now_str}] Không có dữ liệu mới (last_ts={last_ts}).", flush=True)
                else:
                    new_timestamps = sorted(new_df['Timestamp'].unique())
                    print(f"[{now_str}] {len(new_timestamps)} timestamp(s) mới.", flush=True)

                    results_to_insert = []

                    for ts in new_timestamps:
                        group  = new_df[new_df['Timestamp'] == ts].copy()
                        window = buf.push(group)

                        if window is not None:
                            score, is_anomaly = infer_one(window, encoder, det_art, torch_device)
                            status = 'ANOMALY' if is_anomaly else 'normal '
                            ts_str = pd.Timestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                            print(f"  → [{ts_str}] score={score:.4f}  [{status}]",
                                  flush=True)
                            results_to_insert.append({
                                'Timestamp':     ts_str,
                                'score':         round(score, 6),
                                'is_anomaly':    is_anomaly,
                                'detector_type': det_type,
                                'threshold':     round(threshold, 6),
                            })

                    last_ts = new_timestamps[-1]

                    if results_to_insert:
                        try:
                            insert_anomaly_results(client, results_to_insert)
                            n_anom = sum(r['is_anomaly'] for r in results_to_insert)
                            print(f"  → Inserted {len(results_to_insert)} result(s) "
                                  f"({n_anom} anomaly).", flush=True)
                        except Exception as e:
                            print(f"  → [ERROR] Insert failed: {e}", file=sys.stderr,
                                  flush=True)
                            # Recreate client on connection error
                            try:
                                client.close()
                            except Exception:
                                pass
                            client = make_client(CLICKHOUSE_HOST, CLICKHOUSE_HTTP_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD,
                                                 CLICKHOUSE_BASE_PATH, CLICKHOUSE_SECURE)

            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"[{now_str}] [ERROR] {e}", file=sys.stderr, flush=True)
                # Recreate client on connection error
                try:
                    client.close()
                except Exception:
                    pass
                client = make_client(CLICKHOUSE_HOST, CLICKHOUSE_HTTP_PORT, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD,
                                     CLICKHOUSE_BASE_PATH, CLICKHOUSE_SECURE)

            elapsed      = time.time() - loop_start
            time_to_wait = max(0, INTERVAL - elapsed)
            time.sleep(time_to_wait)

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
