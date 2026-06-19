#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GAME=""
GAME_DIR=""
WINE_PREFIX="${WINEPREFIX:-}"
SERVER=""
WINE_BIN="${WON_INSTALLER_WINE:-wine}"
PYTHON_BIN="${WON_INSTALLER_PYTHON:-python3}"
INSTALL_MAPS=0
SKIP_REGISTRY=0
NON_INTERACTIVE=0
FORCE_NEW_KEY=0
KEEP_KEY=0

usage() {
  cat <<'EOF'
Retail WON Linux Wine/Proton helper

Usage:
  install-linux.sh --game homeworld|cataclysm --game-dir PATH --wine-prefix PATH [options]

Options:
  --game VALUE          homeworld or cataclysm
  --game-dir PATH      Game install folder containing Homeworld.exe or Cataclysm.exe
  --wine-prefix PATH   Wine/Proton prefix to update
  --server HOST        Server host to write into NetTweak.script
  --install-maps       Download and install community multiplayer maps
  --skip-maps          Do not install community multiplayer maps
  --skip-registry      Do not write the CD key into the Wine registry
  --force-new-key      Replace any detected CD key with a generated key
  --keep-key           Keep a detected CD key
  --non-interactive    Fail instead of prompting for missing choices
  --help               Show this help
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --game) GAME="${2:-}"; shift 2 ;;
    --game-dir) GAME_DIR="${2:-}"; shift 2 ;;
    --wine-prefix) WINE_PREFIX="${2:-}"; shift 2 ;;
    --server) SERVER="${2:-}"; shift 2 ;;
    --install-maps) INSTALL_MAPS=1; shift ;;
    --skip-maps) INSTALL_MAPS=0; shift ;;
    --skip-registry) SKIP_REGISTRY=1; shift ;;
    --force-new-key) FORCE_NEW_KEY=1; shift ;;
    --keep-key) KEEP_KEY=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

if [[ "$FORCE_NEW_KEY" -eq 1 && "$KEEP_KEY" -eq 1 ]]; then
  die "Use only one of --force-new-key or --keep-key"
fi

product_name() {
  case "$1" in
    homeworld) echo "Homeworld" ;;
    cataclysm) echo "Cataclysm" ;;
    *) die "Unknown game: $1" ;;
  esac
}

default_server() {
  case "$1" in
    homeworld) echo "homeworld.kerrbell.dev" ;;
    cataclysm) echo "cataclysm.kerrbell.dev" ;;
    *) die "Unknown game: $1" ;;
  esac
}

supported_exe_exists() {
  local game="$1"
  local dir="$2"
  case "$game" in
    homeworld) [[ -f "$dir/Homeworld.exe" ]] ;;
    cataclysm) [[ -f "$dir/Cataclysm.exe" || -f "$dir/HomeworldCataclysm.exe" || -f "$dir/Homeworld.exe" ]] ;;
    *) return 1 ;;
  esac
}

write_nettweak() {
  local dir="$1"
  local host="$2"
  cat > "$dir/NetTweak.script" <<EOF
[NetTweak]
TITAN_PICKER_REFRESH_TIME 4.0
TITAN_GAME_EXPIRE_TIME 3600
GAME_PORT 6037
AD_PORT 6038
DIRSERVER_NUM 1
DIRSERVER_PORTS 15101
DIRSERVER_IPSTRINGS $host
PATCHSERVER_NUM 1
PATCHSERVER_PORTS 15101
PATCHSERVER_IPSTRINGS $host
PATCHNAME HomeworldPatch.exe
ROUTING_SERVER_NAME routingserv
CONNECT_TIMEOUT 8000
EOF
}

generate_key_json() {
  local product="$1"
  if [[ -n "${WON_INSTALLER_KEY_JSON:-}" ]]; then
    printf '%s\n' "$WON_INSTALLER_KEY_JSON"
    return
  fi
  "$PYTHON_BIN" "$REPO_ROOT/generate_cdkeys.py" --product "$product" --count 1 --format json
}

json_field() {
  local field="$1"
  "$PYTHON_BIN" -c 'import json, sys; print(json.load(sys.stdin)[0][sys.argv[1]])' "$field"
}

hex_for_reg() {
  "$PYTHON_BIN" -c 'import sys; value=sys.stdin.read().strip(); print(",".join(value[i:i+2].lower() for i in range(0, len(value), 2)))'
}

query_existing_key() {
  local product="$1"
  local prefix="$2"
  WINEPREFIX="$prefix" "$WINE_BIN" reg query "HKLM\\Software\\Sierra On-Line\\$product" /v CDKey 2>/dev/null \
    | awk '/CDKey/ { print $NF; exit }' || true
}

write_registry_key() {
  local game="$1"
  local prefix="$2"
  local product
  product="$(product_name "$game")"

  command -v "$WINE_BIN" >/dev/null 2>&1 || [[ -x "$WINE_BIN" ]] || die "wine was not found. Install Wine or set WON_INSTALLER_WINE."

  local existing_key
  existing_key="$(query_existing_key "$product" "$prefix")"
  if [[ -n "$existing_key" && "$FORCE_NEW_KEY" -eq 0 ]]; then
    if [[ "$KEEP_KEY" -eq 1 || "$NON_INTERACTIVE" -eq 1 ]]; then
      echo "Keeping detected $product CD key: $existing_key"
      return
    fi

    echo "Detected $product CD key: $existing_key"
    read -r -p "Replace it with a generated key? [y/N] " answer
    case "$answer" in
      y|Y|yes|YES) ;;
      *) echo "Keeping detected $product CD key: $existing_key"; return ;;
    esac
  fi

  local key_json display plain encrypted_hex encrypted_reg reg_file
  key_json="$(generate_key_json "$product")"
  display="$(printf '%s' "$key_json" | json_field display_key)"
  plain="$(printf '%s' "$key_json" | json_field plain_key)"
  encrypted_hex="$(printf '%s' "$key_json" | json_field encrypted_key_hex)"
  encrypted_reg="$(printf '%s' "$encrypted_hex" | hex_for_reg)"
  reg_file="$(mktemp)"

  cat > "$reg_file" <<EOF
REGEDIT4

[HKEY_LOCAL_MACHINE\\Software\\WON\\CDKeys]
"$product"=hex:$encrypted_reg

[HKEY_LOCAL_MACHINE\\Software\\Sierra On-Line\\$product]
"CDKey"="$plain"
"${product}OnlineSetupWroteCdKey"=dword:00000001
EOF

  WINEPREFIX="$prefix" "$WINE_BIN" regedit "$reg_file"
  rm -f "$reg_file"
  echo "Wrote generated $product CD key: $display"
}

install_one_game() {
  local game="$1"
  local dir="$2"
  local prefix="$3"
  local host="$4"

  [[ -n "$dir" ]] || die "--game-dir is required"
  [[ -d "$dir" ]] || die "Game folder does not exist: $dir"
  supported_exe_exists "$game" "$dir" || die "No supported executable found in: $dir"
  if [[ "$SKIP_REGISTRY" -eq 0 && -z "$prefix" ]]; then
    die "--wine-prefix is required unless --skip-registry is used"
  fi

  echo "Configuring $(product_name "$game") in $dir"
  write_nettweak "$dir" "$host"
  cp "$REPO_ROOT/keys/kver.kp" "$dir/kver.kp"
  echo "Wrote NetTweak.script and kver.kp"
  if [[ "$SKIP_REGISTRY" -eq 0 ]]; then
    write_registry_key "$game" "$prefix"
  fi
}

[[ -n "$GAME" ]] || die "--game is required"
SERVER="${SERVER:-$(default_server "$GAME")}"

install_one_game "$GAME" "$GAME_DIR" "$WINE_PREFIX" "$SERVER"
