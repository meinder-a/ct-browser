CREATE DATABASE IF NOT EXISTS ct_browser;

CREATE TABLE IF NOT EXISTS ct_browser.cert_events
(
    cert_id       String,
    common_name   LowCardinality(String),
    issuer_o      LowCardinality(String),
    serial_number String,
    update_type   LowCardinality(String),
    log_name      LowCardinality(String),
    sig_alg       LowCardinality(String),
    cert_link     String,
    first_seen    DateTime64(3),
    last_seen     DateTime64(3),
    emitted_at    DateTime64(3),
    expires_at    DateTime64(3)
)
ENGINE = ReplacingMergeTree(last_seen)
PARTITION BY toYYYYMM(first_seen)
ORDER BY (issuer_o, serial_number, common_name)
TTL last_seen + INTERVAL 30 DAY;
