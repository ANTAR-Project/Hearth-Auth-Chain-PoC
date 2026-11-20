#!/bin/bash
set -euo pipefail

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

# Seed auth DB
psql -v ON_ERROR_STOP=1 \
     --username antar_auth \
     --dbname antar_auth \
     --variable owner_username="${HEARTH_OWNER_USERNAME}" \
     --variable owner_password_hash="${HEARTH_OWNER_PASSWORD_HASH}" \
     --variable video_svc_hash="${VIDEO_SVC_SECRET_HASH}" \
     --variable encoding_svc_hash="${ENCODING_SVC_SECRET_HASH}" \
     --variable streaming_svc_hash="${STREAMING_SVC_SECRET_HASH}" \
     --variable gateway_svc_hash="${GATEWAY_SVC_SECRET_HASH}" \
     -f /docker-entrypoint-initdb.d/02-seed-auth.sql

# Seed policy DB
psql -v ON_ERROR_STOP=1 \
     --username antar_policy \
     --dbname antar_policy \
     -f /docker-entrypoint-initdb.d/03-seed-policy.sql