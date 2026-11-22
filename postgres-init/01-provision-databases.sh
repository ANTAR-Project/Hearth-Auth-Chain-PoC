#!/bin/bash
set -euo pipefail

POSTGRES_USER="${POSTGRES_USER}"
AUTH_DB_PASSWORD="${AUTH_DB_PASSWORD}"
POLICY_DB_PASSWORD="${POLICY_DB_PASSWORD}"
STREAMING_DB_PASSWORD="${STREAMING_DB_PASSWORD}"

HEARTH_OWNER_USERNAME="${HEARTH_OWNER_USERNAME}"
HEARTH_OWNER_PASSWORD="${HEARTH_OWNER_PASSWORD}"

VIDEO_SVC_SECRET="${VIDEO_SVC_SECRET}"
ENCODING_SVC_SECRET="${ENCODING_SVC_SECRET}"
STREAMING_SVC_SECRET="${STREAMING_SVC_SECRET}"
GATEWAY_SVC_SECRET="${GATEWAY_SVC_SECRET}"
NOTIFICATION_SVC_SECRET="${NOTIFICATION_SVC_SECRET}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL

  -- auth-service DB
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'antar_auth') THEN
      CREATE ROLE antar_auth WITH LOGIN PASSWORD '${AUTH_DB_PASSWORD}';
    END IF;
  END \$\$;
  SELECT 'CREATE DATABASE antar_auth OWNER antar_auth'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'antar_auth') \gexec

  -- policy-registry DB
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'antar_policy') THEN
      CREATE ROLE antar_policy WITH LOGIN PASSWORD '${POLICY_DB_PASSWORD}';
    END IF;
  END \$\$;
  SELECT 'CREATE DATABASE antar_policy OWNER antar_policy'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'antar_policy') \gexec

  -- streaming DB
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'antar_streaming') THEN
      CREATE ROLE antar_streaming WITH LOGIN PASSWORD '${STREAMING_DB_PASSWORD}';
    END IF;
  END \$\$;
  SELECT 'CREATE DATABASE antar_streaming OWNER antar_streaming'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'antar_streaming') \gexec

EOSQL

# Ensure pgcrypto extension is installed in antar_auth once
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname antar_auth \
     -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"

# Helper to hash a secret using pgcrypto if not already a hash
hash_secret() {
  local val="$1"
  if [[ "$val" =~ ^\{.*\} ]]; then
    echo "$val"
  elif [[ "$val" =~ ^\$2[aby]\$ ]]; then
    echo "{bcrypt}$val"
  else
    local h
    h=$(psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname antar_auth -tA \
         -c "SELECT crypt('$val', gen_salt('bf', 10));" | tr -d '\r\n[:space:]')
    echo "{bcrypt}$h"
  fi
}

OWNER_HASH="$(hash_secret "$HEARTH_OWNER_PASSWORD")"
VIDEO_HASH="$(hash_secret "$VIDEO_SVC_SECRET")"
ENCODING_HASH="$(hash_secret "$ENCODING_SVC_SECRET")"
STREAMING_HASH="$(hash_secret "$STREAMING_SVC_SECRET")"
GATEWAY_HASH="$(hash_secret "$GATEWAY_SVC_SECRET")"
NOTIFICATION_HASH="$(hash_secret "$NOTIFICATION_SVC_SECRET")"

# Seed auth DB
psql -v ON_ERROR_STOP=1 \
     --username antar_auth \
     --dbname antar_auth \
     --variable owner_username="${HEARTH_OWNER_USERNAME}" \
     --variable owner_password_hash="${OWNER_HASH}" \
     --variable video_svc_hash="${VIDEO_HASH}" \
     --variable encoding_svc_hash="${ENCODING_HASH}" \
     --variable streaming_svc_hash="${STREAMING_HASH}" \
     --variable gateway_svc_hash="${GATEWAY_HASH}" \
     --variable notification_svc_hash="${NOTIFICATION_HASH}" \
     -f /docker-entrypoint-initdb.d/sql/02-seed-auth.sql

# Seed policy DB
psql -v ON_ERROR_STOP=1 \
     --username antar_policy \
     --dbname antar_policy \
     -f /docker-entrypoint-initdb.d/sql/03-seed-policy.sql
