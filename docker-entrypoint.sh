#!/bin/sh
set -eu

APP_DIR="/app/won_oss_server"
DATA_DIR="${DATA_DIR:-/data}"
DB_PATH="${DB_PATH:-${DATA_DIR}/won_server.db}"
KEYS_DIR="${KEYS_DIR:-${DATA_DIR}/keys}"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-9100}"
GATEWAY_HOST="${GATEWAY_HOST:-0.0.0.0}"
GATEWAY_PORT="${GATEWAY_PORT:-15101}"
ROUTING_PORT="${ROUTING_PORT:-15100}"
ROUTING_MAX_PORT="${ROUTING_MAX_PORT:-15120}"
FIREWALL_PORT="${FIREWALL_PORT:-2021}"
ADMIN_HOST="${ADMIN_HOST:-0.0.0.0}"
ADMIN_PORT="${ADMIN_PORT:-8080}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
PUBLIC_HOST="${PUBLIC_HOST:-}"

if [ -z "${PUBLIC_HOST}" ]; then
  echo "PUBLIC_HOST must be set so Homeworld clients know which public address to use." >&2
  exit 1
fi

mkdir -p "${DATA_DIR}" "${KEYS_DIR}"

if [ ! -f "${DB_PATH}" ] && [ -f "${APP_DIR}/won_server.db" ]; then
  cp "${APP_DIR}/won_server.db" "${DB_PATH}"
fi

for key_file in authserver_private.der authserver_public.der verifier_private.der verifier_public.der kver.kp; do
  if [ ! -f "${KEYS_DIR}/${key_file}" ] && [ -f "${APP_DIR}/keys/${key_file}" ]; then
    cp "${APP_DIR}/keys/${key_file}" "${KEYS_DIR}/${key_file}"
  fi
done

export APP_DIR
export DB_PATH
export KEYS_DIR
export BACKEND_HOST
export BACKEND_PORT
export GATEWAY_HOST
export GATEWAY_PORT
export ROUTING_PORT
export ROUTING_MAX_PORT
export FIREWALL_PORT
export ADMIN_HOST
export ADMIN_PORT
export LOG_LEVEL
export PUBLIC_HOST

exec python "${APP_DIR}/docker_supervisor.py"
