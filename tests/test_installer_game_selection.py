from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installer" / "hwclient_setup.cs"


def test_interactive_installer_always_offers_both_game_profiles() -> None:
    text = INSTALLER.read_text(encoding="utf-8")

    assert 'private const string ConfigureBothOptionLabel = "Configure both games"' in text
    assert "GameSelectionResult selection = PromptForGameSelection(" in text
    assert "KnownGames," in text
    assert "preferredGame: preferredGame" in text
    assert "preferBoth: detectedTargets.Count == KnownGames.Length" in text


def test_game_picker_explains_missing_game_folders_can_be_selected() -> None:
    text = INSTALLER.read_text(encoding="utf-8")

    assert "Choose Homeworld, Cataclysm, or both." in text
    assert "If a game is not detected, you can select its install folder next." in text
