-- madlib_score.sql — Anomaly scoring and percentile ranking (canonical)
-- Reads centroids from gd_kmeans_output produced by madlib_train.sql

-- Drop prior scored output
DROP TABLE IF EXISTS insider_threat_gold.gd_scored;

-- Assign each employee-window to nearest centroid, compute distance
-- WITH clause must appear before AS in GP CREATE TABLE AS
CREATE TABLE insider_threat_gold.gd_scored
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
AS
SELECT
    ef.employee_id,
    ef.window_end_date,
    (madlib.closest_column(
        km.centroids,
        ef.feature_vector,
        'madlib.squared_dist_norm2'
    )).column_id  AS cluster_id,
    sqrt(
        (madlib.closest_column(
            km.centroids,
            ef.feature_vector,
            'madlib.squared_dist_norm2'
        )).distance
    )             AS anomaly_score
FROM insider_threat_gold.employee_features ef
CROSS JOIN insider_threat_gold.gd_kmeans_output km
DISTRIBUTED BY (employee_id);

-- Percentile rank
SELECT
    employee_id,
    window_end_date,
    cluster_id,
    anomaly_score,
    PERCENT_RANK() OVER (ORDER BY anomaly_score) * 100 AS anomaly_percentile,
    CASE
        WHEN PERCENT_RANK() OVER (ORDER BY anomaly_score) >= 0.95 THEN 'HIGH'
        WHEN PERCENT_RANK() OVER (ORDER BY anomaly_score) >= 0.75 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS anomaly_tier
FROM insider_threat_gold.gd_scored
ORDER BY anomaly_score DESC
LIMIT 20;
