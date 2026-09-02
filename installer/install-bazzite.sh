#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTONTRICKS_APP="com.github.Matoking.protontricks"

GAME=""
GAME_DIR=""
APP_ID=""
INSTALL_MAPS=0

usage() {
  cat <<'EOF'
Bazzite / Steam setup for retail Homeworld and Homeworld: Cataclysm

Run without options for the guided setup:
  bash installer/install-bazzite.sh

Optional advanced usage:
  install-bazzite.sh --game homeworld|cataclysm --game-dir PATH --app-id NUMBER [--install-maps]
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
    --app-id) APP_ID="${2:-}"; shift 2 ;;
    --install-maps) INSTALL_MAPS=1; shift ;;
    --help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

command -v flatpak >/dev/null 2>&1 || die "Flatpak was not found."
flatpak info "$PROTONTRICKS_APP" >/dev/null 2>&1 \
  || die "Protontricks is not installed. Install it from Discover, then try again."
[[ -f "$SCRIPT_DIR/RetailCdKeyGen.exe" ]] \
  || die "RetailCdKeyGen.exe is missing. Download and extract the Linux setup bundle from GitHub Releases, then run this copy of the script."

if [[ -z "$GAME" ]]; then
  echo "Which game are you setting up?"
  echo "  1) Homeworld 1.05"
  echo "  2) Homeworld: Cataclysm 1.0.0.1 / Emergence"
  read -r -p "Enter 1 or 2: " choice
  case "$choice" in
    1) GAME="homeworld" ;;
    2) GAME="cataclysm" ;;
    *) die "Please run the script again and enter 1 or 2." ;;
  esac
fi

[[ "$GAME" == "homeworld" || "$GAME" == "cataclysm" ]] || die "Unknown game: $GAME"

if [[ -z "$GAME_DIR" ]]; then
  echo
  echo "Enter the folder containing the game EXE."
  echo "Tip: you can drag the folder from the file manager into this window."
  read -r -p "Game folder: " GAME_DIR
  GAME_DIR="${GAME_DIR#\'}"; GAME_DIR="${GAME_DIR%\'}"
  GAME_DIR="${GAME_DIR#\"}"; GAME_DIR="${GAME_DIR%\"}"
fi

[[ -d "$GAME_DIR" ]] || die "Game folder does not exist: $GAME_DIR"
GAME_DIR="$(cd "$GAME_DIR" && pwd)"

if [[ -z "$APP_ID" ]]; then
  echo
  echo "Looking for the Steam/Proton shortcut..."
  search_output="$(flatpak run "$PROTONTRICKS_APP" -s "$GAME" 2>&1 || true)"
  printf '%s\n' "$search_output"
  mapfile -t shortcut_ids < <(printf '%s\n' "$search_output" \
    | sed -nE '/Non-Steam shortcut:/s/.*\(([0-9]+)\)$/\1/p')
  if [[ "${#shortcut_ids[@]}" -eq 1 ]]; then
    APP_ID="${shortcut_ids[0]}"
    echo "Using non-Steam shortcut ID: $APP_ID"
  else
    read -r -p "Enter the number in parentheses for the shortcut you use: " APP_ID
  fi
fi

[[ "$APP_ID" =~ ^[0-9]+$ ]] || die "The Steam/Proton app ID must contain numbers only."

if [[ "$INSTALL_MAPS" -eq 0 ]]; then
  read -r -p "Install the optional community map pack? [y/N] " maps_answer
  case "$maps_answer" in y|Y|yes|YES) INSTALL_MAPS=1 ;; esac
fi

echo
echo "Granting Protontricks access to the game and installer folders..."
flatpak override --user \
  --filesystem="$GAME_DIR" \
  --filesystem="$REPO_ROOT:ro" \
  "$PROTONTRICKS_APP"

printf -v script_q '%q' "$SCRIPT_DIR/install-linux.sh"
printf -v game_q '%q' "$GAME"
printf -v game_dir_q '%q' "$GAME_DIR"
inner_command="WON_INSTALLER_WINE=\"\$WINE\" bash $script_q --game $game_q --game-dir $game_dir_q --wine-prefix \"\$WINEPREFIX\""
if [[ "$INSTALL_MAPS" -eq 1 ]]; then
  inner_command+=" --install-maps"
else
  inner_command+=" --skip-maps"
fi

echo "Configuring the game in its Proton prefix..."
flatpak run "$PROTONTRICKS_APP" -c "$inner_command" "$APP_ID"

echo
echo "Setup complete. Close this window and launch the game from the same Steam shortcut."
