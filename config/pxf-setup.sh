#!/usr/bin/env bash
# pxf-setup.sh — Run on the GP host (as gpadmin) to enable PXF → MinIO
# Usage: ssh <gp-host>, then run these commands as gpadmin
#
# After this runs, signal Claude Code to proceed with the external table DDL.

set -euo pipefail

# 1. Find PXF_BASE (adjust if your GP is in a different location)
PXF_BASE="${PXF_BASE:-/usr/local/greenplum-db/pxf}"
if [ ! -d "$PXF_BASE" ]; then
    # Try GPHOME-relative path
    PXF_BASE="$(ls -d /usr/local/greenplum-db-*/pxf 2>/dev/null | head -1)"
fi
echo "Using PXF_BASE=$PXF_BASE"

# 2. Initialize PXF (only needed on first run)
$PXF_BASE/bin/pxf cluster init || true

# 3. Start PXF service on all segment hosts
$PXF_BASE/bin/pxf cluster start
echo "PXF service started."

# 4. Create the MinIO server config directory
mkdir -p "$PXF_BASE/servers/minio"

# 5. Write the s3-site.xml for MinIO
cat > "$PXF_BASE/servers/minio/s3-site.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>fs.s3a.endpoint</name>
    <value>http://127.0.0.1:9000</value>
  </property>
  <property>
    <name>fs.s3a.access.key</name>
    <value>REDACTED_ACCESS_KEY</value>
  </property>
  <property>
    <name>fs.s3a.secret.key</name>
    <value>REDACTED_SECRET_KEY</value>
  </property>
  <property>
    <name>fs.s3a.path.style.access</name>
    <value>true</value>
  </property>
  <property>
    <name>fs.s3a.connection.ssl.enabled</name>
    <value>false</value>
  </property>
  <property>
    <name>fs.s3a.fast.upload</name>
    <value>true</value>
  </property>
</configuration>
XML

echo "MinIO server config written to $PXF_BASE/servers/minio/s3-site.xml"

# 6. Sync config to all segment hosts
$PXF_BASE/bin/pxf cluster sync
echo "PXF config synced."

# 7. Install pxf extension in the database (run as gpadmin or superuser)
psql -d gpadmin -c "CREATE EXTENSION IF NOT EXISTS pxf;"
echo "PXF extension installed in gpadmin."

echo ""
echo "Setup complete. You can now run the Bronze external table DDL."
echo "Test with: psql -d gpadmin -c \"SELECT COUNT(*) FROM insider_threat_bronze.ext_hris_events;\""
