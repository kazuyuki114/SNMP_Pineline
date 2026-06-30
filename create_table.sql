-- Tạo bảng lưu kết quả inference TS2Vec anomaly detection
-- Chạy lệnh này trong ClickHouse Play UI hoặc clickhouse-client

CREATE TABLE IF NOT EXISTS `snmp`.`anomaly_results`
(
    `Timestamp`     DateTime                    COMMENT 'Timestamp của window cuối cùng trong sliding window',
    `score`         Float64                     COMMENT 'Mahalanobis distance hoặc GMM negative log-likelihood',
    `is_anomaly`    UInt8                       COMMENT '1 = anomaly, 0 = normal',
    `detector_type` LowCardinality(String)      COMMENT 'mahal hoặc gmm',
    `threshold`     Float64                     COMMENT 'Ngưỡng phân loại tại thời điểm inference'
)
ENGINE = MergeTree()
ORDER BY Timestamp
SETTINGS index_granularity = 8192;
