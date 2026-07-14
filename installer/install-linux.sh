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
MAP_ARCHIVE_URL="https://github.com/FlashZ/Homeworld_Map_Collection/archive/refs/heads/main.zip"
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

# Legacy shared installer default keys. Early installer builds wrote the same
# hardcoded key for everyone; these are refreshed to a unique random key by
# default, matching the Windows installer's IsLegacySharedRegistryCdKey check.
legacy_shared_key() {
  case "$1" in
    Homeworld) echo "NYX7ZEC9FYZ6GUX84253" ;;
    Cataclysm) echo "GAF6CAB4SEX5ZYL62622" ;;
    *) echo "" ;;
  esac
}

# Strip separators/whitespace and upper-case so display and plain forms compare
# equal (e.g. "NYX7-ZEC9-..." vs "nyx7zec9...").
normalize_cd_key() {
  printf '%s' "$1" | tr -d '\r\n\t -' | tr '[:lower:]' '[:upper:]'
}

is_legacy_shared_key() {
  local product="$1"
  local candidate
  candidate="$(normalize_cd_key "$2")"
  local legacy
  legacy="$(legacy_shared_key "$product")"
  [[ -n "$legacy" && "$candidate" == "$legacy" ]]
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

map_source_dir_name() {
  case "$1" in
    homeworld) echo "HW1_maps" ;;
    cataclysm) echo "CATA_maps" ;;
    *) die "Unknown game: $1" ;;
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
T1_Timeout 30.0
T2_Timeout 14.0
TWAITFORPAUSEACKS_Timeout 14.0
TimedOutWaitingForPauseAcksGiveUpAfterNumTimes 2
HorseRacePlayerDropoutTime 40.0
HorseRaceDroppedOutColor 75,75,75
LAN_ADVERTISE_USER_TIME 0.5
LAN_ADVERTISE_USER_TIMEOUT 3.0
LAN_ADVERTISE_GAME_TIME 0.5
LAN_ADVERTISE_GAME_TIMEOUT 3.0
KEEPALIVE_SEND_IAMALIVE_TIME 10.0
KEEPALIVE_IAMALIVE_TIMEOUT 30.0
KEEPALIVE_SEND_ALIVESTATUS_TIME 30.0
PRINTLAG_IFGREATERTHAN 10
PRINTLAG_MINFRAMES 20
ROOM_MIN_THRESHOLD 1
ROOM_MAX_THRESHOLD 30
WAIT_SHUTDOWN_MS 1000
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
    # An explicit --keep-key always wins. Otherwise a legacy shared installer
    # default is refreshed to a unique key by default (interactive prompt
    # defaults to Yes; non-interactive refreshes silently), so players who
    # installed with an old build stop sharing one key.
    if [[ "$KEEP_KEY" -eq 1 ]]; then
      echo "Keeping detected $product CD key: $existing_key"
      return
    fi

    if is_legacy_shared_key "$product" "$existing_key"; then
      if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        echo "Detected a legacy shared $product installer key ($existing_key); refreshing it with a unique generated key."
      else
        echo "Detected a legacy shared $product installer key: $existing_key"
        echo "This key was shipped to everyone by older installer builds, so replacing it is recommended."
        read -r -p "Replace it with a unique generated key? [Y/n] " answer
        case "$answer" in
          n|N|no|NO) echo "Keeping detected $product CD key: $existing_key"; return ;;
          *) ;;
        esac
      fi
    else
      if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
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

download_maps() {
  local destination="$1"
  if [[ -n "${WON_INSTALLER_MAP_ARCHIVE:-}" ]]; then
    cp "$WON_INSTALLER_MAP_ARCHIVE" "$destination"
    return
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -L --progress-bar "$MAP_ARCHIVE_URL" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then
    wget --show-progress -O "$destination" "$MAP_ARCHIVE_URL"
  else
    die "curl or wget is required to download community maps."
  fi
}

install_maps() {
  local game="$1"
  local dir="$2"
  local source_name
  source_name="$(map_source_dir_name "$game")"

  command -v "$PYTHON_BIN" >/dev/null 2>&1 || [[ -x "$PYTHON_BIN" ]] || die "python3 is required to extract map archives."

  local temp_dir archive source_dir destination copied skipped
  temp_dir="$(mktemp -d)"
  archive="$temp_dir/maps.zip"
  destination="$dir/MultiPlayer"
  copied=0
  skipped=0

  echo "Downloading community maps..."
  download_maps "$archive"
  "$PYTHON_BIN" - "$archive" "$temp_dir/extract" <<'PY'
import sys
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
dest = Path(sys.argv[2])
dest.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive) as zf:
    zf.extractall(dest)
PY

  source_dir="$(find "$temp_dir/extract" -type d -name "$source_name" | head -n 1)"
  [[ -n "$source_dir" ]] || die "Map archive did not contain $source_name."
  mkdir -p "$destination"
  while IFS= read -r map_dir; do
    local target
    target="$destination/$(basename "$map_dir")"
    if [[ -e "$target" ]]; then
      skipped=$((skipped + 1))
      continue
    fi
    cp -R "$map_dir" "$target"
    copied=$((copied + 1))
    echo "Copied $(basename "$map_dir")"
  done < <(find "$source_dir" -mindepth 1 -maxdepth 1 -type d | sort)

  rm -rf "$temp_dir"
  echo "Community maps: copied $copied, skipped $skipped existing."
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
  if [[ "$INSTALL_MAPS" -eq 1 ]]; then
    install_maps "$game" "$dir"
  fi
}

[[ -n "$GAME" ]] || die "--game is required"
SERVER="${SERVER:-$(default_server "$GAME")}"

install_one_game "$GAME" "$GAME_DIR" "$WINE_PREFIX" "$SERVER"
