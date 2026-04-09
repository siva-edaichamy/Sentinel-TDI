-- madlib_train.sql — MADlib k-means training (canonical)
-- MADlib 2.2.0: kmeanspp() returns a result row — store via CREATE TABLE AS
-- Prerequisite: GRANT USAGE ON SCHEMA madlib TO <your_gp_user>;
--               GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA madlib TO <your_gp_user>;

-- Drop prior model output
DROP TABLE IF EXISTS insider_threat_gold.gd_kmeans_output;

-- Train k-means++ on normalized feature vectors
-- k=5 clusters, squared L2 distance, up to 20 iterations
-- WITH clause must appear before AS — DISTRIBUTED clause after the query in GP
CREATE TABLE insider_threat_gold.gd_kmeans_output
WITH (appendoptimized=true, compresstype=zstd, compresslevel=5)
AS
SELECT * FROM madlib.kmeanspp(
    'insider_threat_gold.employee_features',   -- source table
    'feature_vector',                    -- feature column (FLOAT8[])
    5,                          -- k
    'madlib.squared_dist_norm2',         -- distance function
    'madlib.avg',                        -- centroid update function
    20,                   -- max iterations
    0.001::float8           -- convergence tolerance
)
DISTRIBUTED RANDOMLY;

-- Verify: one row with centroids array, num_iterations, objective_fn
SELECT num_iterations, frac_reassigned, objective_fn FROM insider_threat_gold.gd_kmeans_output;
