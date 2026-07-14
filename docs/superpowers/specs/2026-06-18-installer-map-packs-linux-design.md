# Installer Map Packs And Linux Helper Design

Date: 2026-06-18
Project: `won_oss_server`
Primary surfaces: `installer/hwclient_setup.cs`, `installer/install-linux.sh`, `README.md`, release workflow
Status: Written spec awaiting user review

## Summary

This document defines the next installer pass for retail Homeworld and Homeworld: Cataclysm players.

The design adds two player-facing improvements:

- an optional community map-pack installer that downloads maps from `FlashZ/Homeworld_Map_Collection`
- a Linux Wine/Proton helper that performs the same client setup as the Windows installer, including CD-key writing

The Windows installer remains the primary guided GUI experience. The Linux helper is a terminal-first script for people running the retail Windows games under Wine, Proton, Steam, Lutris, or similar prefix-based setups.

## Context

The current Windows installer is a single WinForms program built from `installer/hwclient_setup.cs`. It already:

- detects Homeworld and Homeworld: Cataclysm installs
- lets users configure one game or both detected games
- writes `NetTweak.script`
- writes `kver.kp`
- detects existing registry CD keys
- generates retail-compatible CD keys
- writes Sierra and WON registry key values when enabled
- preserves player-owned keys unless the user confirms replacement

The approved UX direction keeps this installer structure, but makes the detected CD-key decision clearer on the main install screen and adds an optional map-pack install path with visible download progress.

The map collection repository currently documents this layout:

- `HW1_maps/` for Homeworld maps
- `CATA_maps/` for Homeworld: Cataclysm maps

Installation is a folder copy into the game install's `MultiPlayer` directory.

## Goals

- Add an opt-in way to install community multiplayer maps from `FlashZ/Homeworld_Map_Collection`.
- Show map download/copy progress in the Windows GUI.
- Keep the base online setup understandable even when optional map download fails.
- Improve the Windows CD-key UX by showing detected keys and asking whether to keep or replace them before installation begins.
- Add a Linux player-side installer for Wine/Proton users.
- Have the Linux helper write a compatible generated CD key into the selected Wine prefix.
- Keep behavior aligned between Windows and Linux where practical.

## Non-Goals

- Building a Linux server installer. This pass is for players running the retail Windows games under Wine/Proton.
- Rewriting the Windows installer into a new framework.
- Creating a full graphical Linux application.
- Bundling the full map collection inside `RetailWONSetup.exe`.
- Converting maps for Homeworld Remastered.
- Overwriting unrelated game files.

## Design Options Considered

### Option 1: Minimal Windows checkbox and Linux shell script

Add a small `Install community map packs` checkbox to the current GUI, plus a Linux shell script.

Pros:

- Lowest churn
- Fastest to implement
- Keeps the installer compact

Cons:

- Map download behavior is too hidden
- The user may not understand that the installer will use the network
- Does not address the current late CD-key overwrite prompt UX

### Option 2: Optional content panel and Linux shell script

Add a visible `Optional Content` panel to the Windows install screen, with map-pack wording and progress. Replace the late CD-key overwrite surprise with an explicit detected-key section. Add a Linux shell helper with matching prompts.

Pros:

- Best balance of clarity and implementation cost
- Makes map packs discoverable without turning them into a required step
- Brings the CD-key decision forward
- Maps cleanly to a terminal Linux flow

Cons:

- Requires more WinForms layout work
- Requires introducing network download/extract code into the installer

### Option 3: Separate map-install wizard step

After core online setup, show a separate maps screen.

Pros:

- Very explicit
- Gives the map feature room for detail

Cons:

- Makes the installer feel longer
- Adds another step before players can launch the game
- Gives optional maps too much weight compared with the core online setup

### Chosen option

Option 2 was selected and approved.

## Windows Installer UX

The install screen should move toward the approved option-B layout:

1. `Install Folder`
   - Show the detected game folder.
   - Keep the existing `Change...` behavior.
   - Wording should say "Select the exact game folder you launch from."

2. `Online Server`
   - Keep the current default/custom host behavior.
   - Use clearer labels such as `Server:` and `Connect to:`.

3. `CD Key`
   - Show the detected registry key when present.
   - Say whether the key appears player-owned, installer-managed, or legacy shared.
   - Default behavior:
     - player-owned key detected: keep it
     - installer-managed key detected: replace with a generated key
     - legacy shared installer key detected: replace with a generated key
     - no key detected: write a generated key
   - Offer a clear replacement path:
     - `Keep the detected CD key`
     - `Replace it with a new generated key`
     - `Randomize`
   - Avoid surprising the user with a late overwrite dialog after they click `Install` when the screen already captured the choice.

4. `Optional Content`
   - Add an opt-in checkbox:
     - `Install community multiplayer maps`
   - Supporting copy:
     - `Downloads FlashZ/Homeworld_Map_Collection from GitHub and copies maps into MultiPlayer. Existing map folders are left alone by default.`

5. Progress area
   - Show core setup and map progress as visible steps.
   - During map download, show:
     - operation label
     - percent when known
     - downloaded bytes when known
     - current step
   - Example:
     - `Done: NetTweak.script and kver.kp`
     - `Now: 12.4 MB of 32.1 MB from GitHub`
     - `Next: copy maps into MultiPlayer`

The GUI should remain plain, familiar WinForms rather than a heavily styled custom app. The UX improvement is about clarity, sequencing, and wording.

## Windows Map-Pack Behavior

When `Install community multiplayer maps` is checked:

1. Download the repository archive for `FlashZ/Homeworld_Map_Collection`.
2. Extract to a temporary directory.
3. Copy maps into the selected game's `MultiPlayer` directory:
   - Homeworld: `HW1_maps/*`
   - Cataclysm: `CATA_maps/*`
4. Create `MultiPlayer` if it does not exist.
5. Skip existing destination map folders by default.
6. Report skipped and copied map counts in the success message.

Map download/copy failures should not undo base online setup.

If base setup succeeds but maps fail, the result should clearly say:

- online setup succeeded
- map installation failed or was skipped
- the user can rerun the installer later to install maps

## Linux Wine/Proton Helper

Add `installer/install-linux.sh`.

The script is a player-side helper for Linux users running the retail Windows game under Wine/Proton.

### Command-line shape

Initial flags:

- `--game homeworld|cataclysm|both`
- `--game-dir PATH`
- `--wine-prefix PATH`
- `--server HOST`
- `--install-maps`
- `--skip-maps`
- `--skip-registry`
- `--force-new-key`
- `--keep-key`
- `--non-interactive`
- `--help`

Names can be adjusted during implementation if shell conventions suggest clearer wording.

### Detection

The Linux helper should try practical, conservative detection:

- explicit `--game-dir` and `--wine-prefix` first
- current working directory if it contains a supported game executable
- common Wine prefix path:
  - `$WINEPREFIX`
  - `~/.wine`
- common Steam/Proton paths where feasible:
  - Steam library `steamapps/compatdata/*/pfx`
  - game folders under Steam libraries when discoverable
- common Lutris-style Wine prefixes when discoverable without fragile assumptions

If detection is ambiguous, prompt the user rather than guessing.

The script should accept manual paths as the reliable escape hatch.

### File setup

For each selected game, the script should:

- validate the selected game folder by checking supported executable names
- write `NetTweak.script`
- write `kver.kp`
- optionally install maps into `MultiPlayer`

The Linux script should use the same default server hosts and NetTweak intent as the Windows installer.

### Wine registry setup

The script should write the CD key unless `--skip-registry` is passed.

It should:

1. Use the selected Wine prefix.
2. Query the current registry values when possible.
3. Show the current formatted key if present.
4. Default to keeping player-owned keys.
5. Default to replacing installer-managed or legacy shared keys.
6. Generate a new retail-compatible key when needed.
7. Write the Sierra and WON registry values through `wine reg` or an equivalent Wine-safe registry mechanism.

If `wine` is missing or registry writes fail, the script should stop before claiming the install is complete and explain what is missing.

### Linux map progress

The shell helper should show progress when downloading maps:

- use `curl --progress-bar` or `wget --show-progress` when available
- fall back to clear step messages if byte-level progress is unavailable
- show copy progress as counts, such as `Copied 24 maps, skipped 3 existing`

## Shared Behavior And Constants

Windows and Linux should stay aligned on:

- supported game keys
- display names
- default server hosts
- supported executable names
- default NetTweak templates
- `kver.kp` bytes
- CD-key generation rules
- legacy shared key detection
- map repository source
- source subdirectories for Homeworld and Cataclysm maps

Implementation may duplicate some constants at first if that avoids a risky rewrite, but the duplication should be obvious and easy to compare.

## Error Handling

### Base setup failures

Failures writing `NetTweak.script`, `kver.kp`, or registry values should fail the selected game setup and clearly report the problem.

### Map failures

Map failures are optional-content failures.

They should:

- be reported clearly
- not hide successful online setup
- not leave temporary files behind where practical
- not overwrite existing maps unless a future explicit refresh option is added

### Network behavior

Map download requires internet access and GitHub availability.

The installer should say that before starting the download. If GitHub is unavailable, the message should be practical rather than alarming.

## Documentation

Update player-facing documentation to cover:

- the optional map-pack checkbox
- what map installation changes
- map source repository
- Linux Wine/Proton helper usage
- how to pass explicit game and Wine prefix paths
- how CD-key detection/replacement works

Update release notes or release workflow if the Linux script should be attached to installer releases.

## Validation Plan

### Windows

- Build `RetailWONSetup.exe`.
- Validate the revised form layout at normal Windows scaling.
- Validate the detected-key states:
  - no key
  - player-owned key
  - installer-managed key
  - legacy shared key
- Validate map download progress with a real or controlled download.
- Validate map-copy behavior into a temporary fake game install.
- Validate optional map failure still reports base setup success.

### Linux

- Run shellcheck if available.
- Run script dry-run or test helpers against temporary fake game folders.
- Validate required argument parsing.
- Validate missing `wine`, missing game folder, and missing prefix messages.
- Validate registry command construction with test doubles where possible.
- Validate map download/copy behavior with a temporary destination.

### Docs

- Check README instructions match actual flags and wording.
- Check that Windows and Linux descriptions do not imply Remastered support.

## Acceptance Criteria

The installer pass is successful when:

1. Windows users can opt into community maps from the main installer screen.
2. Windows users see download/copy progress for map installation.
3. Windows users see detected CD-key state before installation and can keep or replace the key.
4. Linux Wine/Proton users can configure Homeworld and/or Cataclysm from a terminal script.
5. The Linux helper writes the generated CD key into the selected Wine prefix by default.
6. Optional map failures do not obscure a successful base online setup.
7. Documentation explains both the map feature and Linux helper clearly.

## Risks

- GitHub archive downloads add a network dependency to an otherwise local installer flow.
- WinForms progress code can become awkward if mixed too deeply into the existing single-file installer.
- Wine/Proton install detection can never be perfect across every distro, launcher, and library layout.
- Writing registry values into Wine prefixes needs careful messaging so users understand which prefix is being changed.
- Duplicating Windows constants in shell could drift over time if not kept visibly organized.

These risks are acceptable if the implementation keeps manual path overrides strong, progress/error messages clear, and optional maps separate from the base online setup result.

## Recommendation

Proceed with:

1. a revised Windows installer main screen based on the approved option-B mockup
2. explicit detected-key keep/replace choices
3. opt-in map packs with progress and conservative copy behavior
4. a Linux Wine/Proton shell helper with CD-key registry writing enabled by default

Implementation should prioritize UX clarity over clever detection. When in doubt, show what was detected and let the user choose.
