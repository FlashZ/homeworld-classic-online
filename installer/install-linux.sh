#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GAME=""
GAME_DIR=""
WINE_PREFIX="${WINEPREFIX:-}"
SERVER=""
INSTALL_MAPS=0
SKIP_REGISTRY=0
NON_INTERACTIVE=0

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
    --force-new-key|--keep-key) shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

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
}

[[ -n "$GAME" ]] || die "--game is required"
SERVER="${SERVER:-$(default_server "$GAME")}"

install_one_game "$GAME" "$GAME_DIR" "$WINE_PREFIX" "$SERVER"
