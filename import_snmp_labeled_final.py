#!/usr/bin/env python3
import base64
import csv
import http.client
import os
import sys
from pathlib import Path
from urllib.parse import urlencode


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CSV_PATH = ROOT_DIR / "snmp_labeled_final.csv"

# Edit these values directly when you want to import into another table.
CLICKHOUSE_DATABASE = "snmp"
CLICKHOUSE_TABLE = "snmp_labeled_final"
CSV_PATH = DEFAULT_CSV_PATH

# Connection defaults. User/password can still come from .env.
CLICKHOUSE_HOST = "grad-thesis-hust.duckdns.org"
CLICKHOUSE_HTTP_PORT = 80
CLICKHOUSE_BASE_PATH = "/clickhouse"
CLICKHOUSE_SECURE = False

COLUMNS = [
    "Timestamp",
    "Device",
    "IP",
    "tcpActiveOpens",
    "tcpCurrEstab",
    "tcpEstabResets",
    "tcpInSegs",
    "tcpOutRsts",
    "tcpOutSegs",
    "tcpPassiveOpens",
    "tcpRetransSegs",
    "udpInDatagrams",
    "udpInErrors",
    "udpNoPorts",
    "udpOutDatagrams",
    "ipForwDatagrams",
    "ipInAddrErrors",
    "ipInDelivers",
    "ipInDiscards",
    "ipInReceives",
    "ipOutNoRoutes",
    "ipOutDiscards",
    "ipOutRequests",
    "icmpInDestUnreachs",
    "icmpInEchos",
    "icmpInMsgs",
    "icmpOutDestUnreachs",
    "icmpOutEchoReps",
    "icmpOutMsgs",
    "ifInOctets_enp0s3",
    "ifInUcastPkts_enp0s3",
    "ifInNUcastPkts_enp0s3",
    "ifInDiscards_enp0s3",
    "ifOutOctets_enp0s3",
    "ifOutUcastPkts_enp0s3",
    "ifOutNUcastPkts_enp0s3",
    "ifOutDiscards_enp0s3",
    "ifInOctets_enp0s8",
    "ifInUcastPkts_enp0s8",
    "ifInNUcastPkts_enp0s8",
    "ifInDiscards_enp0s8",
    "ifOutOctets_enp0s8",
    "ifOutUcastPkts_enp0s8",
    "ifOutNUcastPkts_enp0s8",
    "ifOutDiscards_enp0s8",
    "ifInOctets_enp0s9",
    "ifInUcastPkts_enp0s9",
    "ifInNUcastPkts_enp0s9",
    "ifInDiscards_enp0s9",
    "ifOutOctets_enp0s9",
    "ifOutUcastPkts_enp0s9",
    "ifOutNUcastPkts_enp0s9",
    "ifOutDiscards_enp0s9",
    "ifInOctets_enp0s10",
    "ifInUcastPkts_enp0s10",
    "ifInNUcastPkts_enp0s10",
    "ifInDiscards_enp0s10",
    "ifOutOctets_enp0s10",
    "ifOutUcastPkts_enp0s10",
    "ifOutNUcastPkts_enp0s10",
    "ifOutDiscards_enp0s10",
    "label",
    "label_id",
]


def load_env(path):
    env = {}
    if not path.exists():
        return env

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'\"")
    return env


def quote_identifier(identifier):
    return f"`{identifier.replace('`', '``')}`"


def full_table_name(database, table):
    return f"{quote_identifier(database)}.{quote_identifier(table)}"


class ClickHouseHTTP:
    def __init__(self, host, port, user, password, secure=False, timeout=120, base_path=""):
        connection_cls = http.client.HTTPSConnection if secure else http.client.HTTPConnection
        self.conn = connection_cls(host, port, timeout=timeout)
        self.base_path = base_path.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        self.base_headers = {"Authorization": f"Basic {token}"}

    def query(self, sql, body=None, content_type="text/plain; charset=utf-8"):
        headers = dict(self.base_headers)
        headers["Content-Type"] = content_type
        path = self.base_path + "/?" + urlencode({"query": sql})

        self.conn.request("POST", path, body=body, headers=headers, encode_chunked=body is not None)
        response = self.conn.getresponse()
        response_body = response.read().decode("utf-8", errors="replace")
        if response.status >= 300:
            raise RuntimeError(f"ClickHouse HTTP {response.status}: {response_body}")
        return response_body

    def close(self):
        self.conn.close()


def validate_csv_header(csv_path):
    with csv_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.reader(csv_file)
        header = next(reader, [])

    if header != COLUMNS:
        missing = [name for name in COLUMNS if name not in header]
        extra = [name for name in header if name not in COLUMNS]
        raise ValueError(
            "CSV header does not match the ClickHouse schema. "
            f"Missing: {missing or 'none'}; extra: {extra or 'none'}"
        )


def main():
    env = load_env(ROOT_DIR / ".env")
    database = CLICKHOUSE_DATABASE
    table = CLICKHOUSE_TABLE
    user = env.get("CLICKHOUSE_USER") or os.getenv("CLICKHOUSE_USER") or "admin"
    password = (
        env.get("CLICKHOUSE_PASSWORD")
        or os.getenv("CLICKHOUSE_PASSWORD")
        or "changeme"
    )

    csv_path = Path(CSV_PATH).expanduser().resolve()
    if not csv_path.is_file():
        print(f"CSV file not found: {csv_path}", file=sys.stderr)
        return 1
    validate_csv_header(csv_path)

    client = ClickHouseHTTP(
        CLICKHOUSE_HOST,
        CLICKHOUSE_HTTP_PORT,
        user,
        password,
        secure=CLICKHOUSE_SECURE,
        base_path=CLICKHOUSE_BASE_PATH,
    )
    try:
        insert_sql = f"INSERT INTO {full_table_name(database, table)} FORMAT CSVWithNames"
        with csv_path.open("rb") as csv_file:
            client.query(insert_sql, body=csv_file, content_type="text/csv")

        count = client.query(f"SELECT count() FROM {full_table_name(database, table)}").strip()
        print(f"Imported {csv_path.name}. Current row count: {count}")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
