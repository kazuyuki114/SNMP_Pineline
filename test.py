#!/usr/bin/env python3
"""
test.py
-------
Script độc lập để kiểm tra kết nối và đọc dữ liệu từ ClickHouse qua HTTPS,
không phụ thuộc vào collect_data.py / infer_realtime.py.

Usage:
    python test.py
"""

import requests

# --- ClickHouse Configuration ---
# Điền tay các giá trị bên dưới trước khi chạy.
CLICKHOUSE_HOST = ""
CLICKHOUSE_HTTP_PORT = 443
CLICKHOUSE_BASE_PATH = "/clickhouse"
CLICKHOUSE_SECURE = True
CLICKHOUSE_USER = ""
CLICKHOUSE_PASSWORD = ""

CLICKHOUSE_DATABASE = "snmp"
CLICKHOUSE_TABLE = "snmp_labeled_final"


def clickhouse_query(sql):
    scheme = "https" if CLICKHOUSE_SECURE else "http"
    url = f"{scheme}://{CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT}{CLICKHOUSE_BASE_PATH}/"
    response = requests.post(
        url,
        params={"query": sql},
        auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
        timeout=10,
    )
    response.raise_for_status()
    return response.text


def main():
    print(f"Connecting to ClickHouse at {CLICKHOUSE_HOST}:{CLICKHOUSE_HTTP_PORT}{CLICKHOUSE_BASE_PATH} ...")

    ping = clickhouse_query("SELECT 1")
    print(f"Ping: {ping.strip()}")

    count = clickhouse_query(f"SELECT count() FROM {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE}")
    print(f"Row count in {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE}: {count.strip()}")

    sample = clickhouse_query(
        f"SELECT * FROM {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE} "
        f"ORDER BY Timestamp DESC LIMIT 5 FORMAT PrettyCompact"
    )
    print("\nLast 5 rows:")
    print(sample)


if __name__ == "__main__":
    main()
