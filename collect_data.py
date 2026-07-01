import base64
import csv
import http.client
import io
import time
import asyncio
from datetime import datetime
from urllib.parse import urlencode
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
)

# --- Configuration ---
COMMUNITY = 'public'
INTERVAL = 15

CLICKHOUSE_HOST = ""
CLICKHOUSE_HTTP_PORT = 443
CLICKHOUSE_BASE_PATH = "/clickhouse"
CLICKHOUSE_SECURE = True
CLICKHOUSE_USER = ""
CLICKHOUSE_PASSWORD = ""
CLICKHOUSE_DATABASE = "snmp"
CLICKHOUSE_TABLE = "snmp_labeled_final"

# Default label for live SNMP data.
DEFAULT_LABEL = "Normal"
DEFAULT_LABEL_ID = 0

# Single shared SNMP engine (pysnmp v6 requirement)
snmp_engine = SnmpEngine()

# Define all devices to poll: name -> IP
DEVICES = {
    'device1': '172.16.0.80',
    'device2': '172.16.0.1',
    'device3': '10.0.0.1',
    'device4': '192.168.10.10'
}

DEVICE_INTERFACES = {
    'device1': {
        'enp0s3':  2,
        'enp0s8':  3,
        'enp0s9':  4,
        'enp0s10': 5,
    },
    'device2': {
        'enp0s3':  2,
        'enp0s8':  3,
        'enp0s9':  4,
        'enp0s10': 5,
    },
    'device3': {
        'enp0s3':  2,
        'enp0s8':  3,
        'enp0s9':  4,
        'enp0s10': 5,
    },
    'device4': {
        'enp0s3':  2,
        'enp0s8':  3,
        'enp0s9':  4,
        'enp0s10': 5,
    },
    'device5': {
        'enp0s3':  2,
        'enp0s8':  3,
        'enp0s9':  4,
        'enp0s10': 5,
    },
}

# --- Global OIDs (same for all devices, no interface index needed) ---
GLOBAL_OIDS = {
    # TCP Group
    'tcpActiveOpens':      '1.3.6.1.2.1.6.5.0',
    'tcpCurrEstab':        '1.3.6.1.2.1.6.9.0',
    'tcpEstabResets':      '1.3.6.1.2.1.6.8.0',
    'tcpInSegs':           '1.3.6.1.2.1.6.10.0',
    'tcpOutRsts':          '1.3.6.1.2.1.6.15.0',
    'tcpOutSegs':          '1.3.6.1.2.1.6.11.0',
    'tcpPassiveOpens':     '1.3.6.1.2.1.6.6.0',
    'tcpRetransSegs':      '1.3.6.1.2.1.6.12.0',

    # UDP Group
    'udpInDatagrams':      '1.3.6.1.2.1.7.1.0',
    'udpInErrors':         '1.3.6.1.2.1.7.3.0',
    'udpNoPorts':          '1.3.6.1.2.1.7.2.0',
    'udpOutDatagrams':     '1.3.6.1.2.1.7.4.0',

    # IP Group
    'ipForwDatagrams':     '1.3.6.1.2.1.4.6.0',
    'ipInAddrErrors':      '1.3.6.1.2.1.4.5.0',
    'ipInDelivers':        '1.3.6.1.2.1.4.9.0',
    'ipInDiscards':        '1.3.6.1.2.1.4.8.0',
    'ipInReceives':        '1.3.6.1.2.1.4.3.0',
    'ipOutNoRoutes':       '1.3.6.1.2.1.4.12.0',
    'ipOutDiscards':       '1.3.6.1.2.1.4.11.0',
    'ipOutRequests':       '1.3.6.1.2.1.4.10.0',

    # ICMP Group
    'icmpInDestUnreachs':  '1.3.6.1.2.1.5.3.0',
    'icmpInEchos':         '1.3.6.1.2.1.5.8.0',
    'icmpInMsgs':          '1.3.6.1.2.1.5.1.0',
    'icmpOutDestUnreachs': '1.3.6.1.2.1.5.16.0',
    'icmpOutEchoReps':     '1.3.6.1.2.1.5.22.0',
    'icmpOutMsgs':         '1.3.6.1.2.1.5.14.0',
}

# --- Per-interface OID templates ---
INTERFACE_OID_TEMPLATES = {
    'ifInOctets':      '1.3.6.1.2.1.2.2.1.10',
    'ifInUcastPkts':   '1.3.6.1.2.1.2.2.1.11',
    'ifInNUcastPkts':  '1.3.6.1.2.1.2.2.1.12',
    'ifInDiscards':    '1.3.6.1.2.1.2.2.1.13',
    'ifOutOctets':     '1.3.6.1.2.1.2.2.1.16',
    'ifOutUcastPkts':  '1.3.6.1.2.1.2.2.1.17',
    'ifOutNUcastPkts': '1.3.6.1.2.1.2.2.1.18',
    'ifOutDiscards':   '1.3.6.1.2.1.2.2.1.19',
}


def quote_identifier(identifier):
    return f"`{identifier.replace('`', '``')}`"


def full_table_name(database, table):
    return f"{quote_identifier(database)}.{quote_identifier(table)}"


def column_list(columns):
    return ", ".join(quote_identifier(col) for col in columns)


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


def build_oids_for_device(device_name):
    oids = dict(GLOBAL_OIDS)
    interfaces = DEVICE_INTERFACES.get(device_name, {})
    for iface_name, if_index in interfaces.items():
        for counter_name, oid_base in INTERFACE_OID_TEMPLATES.items():
            oids[f"{counter_name}_{iface_name}"] = f"{oid_base}.{if_index}"
    return oids


def build_columns(device_configs):
    all_oid_columns = []
    seen = set()
    for cfg in device_configs.values():
        for col_name in cfg['oids'].keys():
            if col_name not in seen:
                all_oid_columns.append(col_name)
                seen.add(col_name)
    return ['Timestamp', 'Device', 'IP'] + all_oid_columns + ['label', 'label_id']


def rows_to_csv(rows, columns):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        normalized = {col: row.get(col, 0) for col in columns}
        normalized['label'] = row.get('label', DEFAULT_LABEL)
        normalized['label_id'] = row.get('label_id', DEFAULT_LABEL_ID)
        writer.writerow(normalized)
    return output.getvalue()


def insert_rows(client, rows, columns):
    if not rows:
        return
    insert_sql = (
        f"INSERT INTO {full_table_name(CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE)} "
        f"({column_list(columns)}) FORMAT CSVWithNames"
    )
    csv_body = rows_to_csv(rows, columns)
    client.query(insert_sql, body=csv_body.encode("utf-8"), content_type="text/csv")


async def get_snmp_value(ip, community, oid):
    try:
        target = await UdpTransportTarget.create((ip, 161), timeout=2.0, retries=2)
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmp_engine,
            CommunityData(community),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        if errorIndication or errorStatus:
            return 0
        val = varBinds[0][1].prettyPrint()
        if 'No Such' in val or 'noSuch' in val or 'endOfMib' in val or val == '':
            return 0
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0
    except Exception:
        return 0


async def poll_all_oids(ip, community, oids_dict):
    names = list(oids_dict.keys())
    coros = [get_snmp_value(ip, community, oids_dict[name]) for name in names]
    values = await asyncio.gather(*coros)
    results = dict(zip(names, values))

    if all(v == 0 for v in values):
        print(f"\n  [{ip}] WARNING: all {len(names)} OIDs returned 0 — device unreachable or SNMP misconfigured", flush=True)

    return results


async def poll_device(device_name, device_ip, oids_dict, timestamp):
    row_data = {
        'Timestamp': timestamp,
        'Device': device_name,
        'IP': device_ip,
        'label': DEFAULT_LABEL,
        'label_id': DEFAULT_LABEL_ID,
    }
    oid_results = await poll_all_oids(device_ip, COMMUNITY, oids_dict)
    row_data.update(oid_results)
    return row_data


async def main_loop():
    device_configs = {}
    for device_name, device_ip in DEVICES.items():
        oids = build_oids_for_device(device_name)
        device_configs[device_name] = {'ip': device_ip, 'oids': oids}

    clickhouse_columns = build_columns(device_configs)
    total_oids = sum(len(cfg['oids']) for cfg in device_configs.values())

    print(f"--- Starting SNMP Poller ---")
    print(f"Devices: {len(DEVICES)} ({', '.join(DEVICES.keys())})")
    print(f"Total OIDs across all devices: {total_oids}")
    print(f"ClickHouse columns: {len(clickhouse_columns)}")
    for name, cfg in device_configs.items():
        ifaces = list(DEVICE_INTERFACES.get(name, {}).keys())
        print(f"  {name} ({cfg['ip']}): {len(cfg['oids'])} OIDs, "
              f"interfaces: {', '.join(ifaces) if ifaces else 'none'}")
    print(f"Saving to: {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE}")
    print(f"ClickHouse: {CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT}{CLICKHOUSE_BASE_PATH}")
    print(f"Interval: {INTERVAL}s")
    print("Press Ctrl+C to stop.\n")

    client = ClickHouseHTTP(
        CLICKHOUSE_HOST,
        CLICKHOUSE_HTTP_PORT,
        CLICKHOUSE_USER,
        CLICKHOUSE_PASSWORD,
        secure=CLICKHOUSE_SECURE,
        base_path=CLICKHOUSE_BASE_PATH,
    )

    try:
        while True:
            start_time = time.time()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            print(f"[{timestamp}] Polling {len(DEVICES)} devices...", end=" ", flush=True)

            tasks = [
                poll_device(device_name, cfg['ip'], cfg['oids'], timestamp)
                for device_name, cfg in device_configs.items()
            ]
            results = await asyncio.gather(*tasks)

            device_names = [r['Device'] for r in results]
            try:
                insert_rows(client, results, clickhouse_columns)
                print(f"Inserted ({', '.join(device_names)}).")
            except Exception as e:
                print(f"ClickHouse insert failed: {e}")

            elapsed = time.time() - start_time
            time_to_wait = max(0, INTERVAL - elapsed)
            await asyncio.sleep(time_to_wait)

    except KeyboardInterrupt:
        print("\nScript stopped by user.")
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(main_loop())
