#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48
  fi
}

prompt() {
  local label="$1"
  local default_value="${2:-}"
  local result
  if [[ -n "$default_value" ]]; then
    read -r -p "$label [$default_value]: " result
    printf '%s' "${result:-$default_value}"
  else
    read -r -p "$label: " result
    printf '%s' "$result"
  fi
}

prompt_yes_no() {
  local label="$1"
  local default_value="${2:-y}"
  local result
  read -r -p "$label [${default_value}/$( [[ "$default_value" == "y" ]] && printf 'n' || printf 'y' )]: " result
  result="${result:-$default_value}"
  [[ "$result" == "y" || "$result" == "Y" ]]
}

printf '\nXAM Linux Server deploy helper\n'
printf 'Repository: %s\n\n' "$ROOT_DIR"

if [[ -f "$ENV_FILE" ]]; then
  if ! prompt_yes_no ".env already exists. Overwrite it?" "n"; then
    printf 'Keeping existing .env. Nothing changed.\n'
    exit 0
  fi
fi

APP_BIND_ADDRESS="$(prompt "Bind API to host address" "127.0.0.1")"
APP_PORT="$(prompt "Host port for API" "8080")"
POSTGRES_DB="$(prompt "Postgres database name" "messenger")"
POSTGRES_USER="$(prompt "Postgres user" "messenger")"
POSTGRES_PASSWORD="$(prompt "Postgres password" "$(generate_secret)")"
JWT_SECRET="$(prompt "JWT secret" "$(generate_secret)")"
MINIO_ROOT_USER="$(prompt "MinIO root user" "minioadmin")"
MINIO_ROOT_PASSWORD="$(prompt "MinIO root password" "$(generate_secret)")"
DEBUG_API_ENABLED="false"
if prompt_yes_no "Enable debug API endpoints?" "n"; then
  DEBUG_API_ENABLED="true"
fi

cat >"$ENV_FILE" <<EOF
HTTP_ADDRESS=:8080
APP_BIND_ADDRESS=$APP_BIND_ADDRESS
APP_PORT=$APP_PORT
POSTGRES_DB=$POSTGRES_DB
POSTGRES_USER=$POSTGRES_USER
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
DATABASE_URL=postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@postgres:5432/$POSTGRES_DB?sslmode=disable
JWT_SECRET=$JWT_SECRET
TOKEN_TTL=24h
CHALLENGE_TTL=5m
MESSAGE_TTL=720h
CLEANUP_INTERVAL=10m
PULL_LIMIT_DEFAULT=50
PULL_LIMIT_MAX=200
MAX_CIPHERTEXT_BYTES=1048576
MAX_ATTACHMENT_BYTES=104857600
MAX_ACK_ITEMS=500
RATE_AUTH_PER_MINUTE=30
RATE_SEND_PER_MINUTE=120
RATE_PULL_PER_MINUTE=240
S3_ENDPOINT=minio:9000
MINIO_ROOT_USER=$MINIO_ROOT_USER
MINIO_ROOT_PASSWORD=$MINIO_ROOT_PASSWORD
S3_ACCESS_KEY=$MINIO_ROOT_USER
S3_SECRET_KEY=$MINIO_ROOT_PASSWORD
S3_BUCKET=messenger
S3_USE_SSL=false
PRESIGN_TTL=15m
LOG_LEVEL=INFO
DEBUG_API_ENABLED=$DEBUG_API_ENABLED
DEBUG_LOG_BUFFER=500
EOF

printf '\nCreated %s\n' "$ENV_FILE"
printf 'API will be reachable at http://%s:%s\n' "$APP_BIND_ADDRESS" "$APP_PORT"

if prompt_yes_no "Run docker compose up -d --build now?" "y"; then
  cd "$ROOT_DIR"
  docker compose --env-file .env up -d --build
  printf '\nDeployment started.\n'
  printf 'Health check: curl http://%s:%s/healthz\n' "$APP_BIND_ADDRESS" "$APP_PORT"
else
  printf '\nNext step:\n'
  printf 'cd %s && docker compose --env-file .env up -d --build\n' "$ROOT_DIR"
fi
