-- analytics_queries.sql — s6_report_analytics dashboard and executive report queries

-- 1. Top 25 highest-risk employees (latest window)
SELECT
    e.employee_id,
    h.full_name,
    h.department,
    h.role_title,
    h.clearance_level,
    e.anomaly_score,
    e.anomaly_percentile,
    e.anomaly_tier,
    e.cross_domain_anomaly_count,
    e.window_end_date
FROM insider_threat_gold.employee_risk_features e
JOIN insider_threat_silver.sv_hris h USING (employee_id)
WHERE e.window_end_date = (SELECT MAX(window_end_date) FROM insider_threat_gold.employee_risk_features)
  AND e.anomaly_tier = 'HIGH'
ORDER BY e.anomaly_score DESC
LIMIT 25;

-- 2. Risk trend over time for HIGH-tier employees
SELECT
    employee_id,
    window_end_date,
    anomaly_score,
    anomaly_tier,
    cross_domain_anomaly_count
FROM insider_threat_gold.employee_risk_features
WHERE employee_id IN (
    SELECT employee_id
    FROM insider_threat_gold.employee_risk_features
    WHERE anomaly_tier = 'HIGH'
    GROUP BY employee_id
    HAVING COUNT(*) >= 3
)
ORDER BY employee_id, window_end_date;

-- 3. Cluster population summary
SELECT
    cluster_id,
    COUNT(DISTINCT employee_id) AS employees,
    COUNT(*) AS windows,
    ROUND(AVG(anomaly_score)::numeric, 4) AS avg_score,
    ROUND(MAX(anomaly_score)::numeric, 4) AS max_score,
    ROUND(AVG(cross_domain_anomaly_count)::numeric, 2) AS avg_domains_flagged
FROM insider_threat_gold.employee_risk_features
GROUP BY cluster_id
ORDER BY avg_score DESC;

-- 4. Domain signal contribution (which features drive HIGH tier)
SELECT
    anomaly_tier,
    ROUND(AVG(badge_swipes_outlier)::numeric, 3)        AS avg_badge_outlier,
    ROUND(AVG(after_hours_pacs_score)::numeric, 3)      AS avg_ah_pacs,
    ROUND(AVG(after_hours_network_score)::numeric, 3)   AS avg_ah_network,
    ROUND(AVG(usb_exfiltration_score)::numeric, 3)      AS avg_usb_score,
    ROUND(AVG(file_movement_outlier)::numeric, 3)       AS avg_file_movement,
    ROUND(AVG(vpn_anomaly_score)::numeric, 3)           AS avg_vpn_score,
    ROUND(AVG(comms_volume_delta)::numeric, 3)          AS avg_comms_delta,
    ROUND(AVG(sentiment_trend)::numeric, 3)             AS avg_sentiment_trend,
    SUM(CASE WHEN impossible_travel_flag THEN 1 ELSE 0 END) AS impossible_travel_count,
    SUM(CASE WHEN clearance_anomaly_flag THEN 1 ELSE 0 END) AS clearance_anomaly_count
FROM insider_threat_gold.employee_risk_features
GROUP BY anomaly_tier
ORDER BY anomaly_tier;

-- 5. Identity resolution audit
SELECT
    source_domain,
    identity_resolution_status,
    COUNT(*) AS record_count
FROM (
    SELECT 'pacs'         AS source_domain, identity_resolution_status FROM insider_threat_silver.sv_pacs
    UNION ALL
    SELECT 'network',     identity_resolution_status FROM insider_threat_silver.sv_network
    UNION ALL
    SELECT 'dlp',         identity_resolution_status FROM insider_threat_silver.sv_dlp
    UNION ALL
    SELECT 'comms',       identity_resolution_status FROM insider_threat_silver.sv_comms
    UNION ALL
    SELECT 'pai',         identity_resolution_status FROM insider_threat_silver.sv_pai
    UNION ALL
    SELECT 'geo',         identity_resolution_status FROM insider_threat_silver.sv_geo
    UNION ALL
    SELECT 'adjudication',identity_resolution_status FROM insider_threat_silver.sv_adjudication
) domains
GROUP BY source_domain, identity_resolution_status
ORDER BY source_domain, identity_resolution_status;

-- 6. Pipeline lineage audit
SELECT run_id, stage_name, status, rows_in, rows_out, duration_seconds, started_at
FROM insider_threat_bronze.pipeline_runs
ORDER BY started_at DESC
LIMIT 20;
