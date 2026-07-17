from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installer" / "hwclient_setup.cs"


def test_map_pack_choice_is_visible_in_the_install_dialog() -> None:
    text = INSTALLER.read_text(encoding="utf-8")

    assert 'optionalContentGroup.Text = "Optional Content"' in text
    assert "form.Controls.Add(optionalContentGroup);" in text
    assert 'installMapsCheckBox.Text = "Download and install community map pack"' in text


def test_install_dialog_reserves_space_for_multiline_help_text() -> None:
    text = INSTALLER.read_text(encoding="utf-8")

    assert "form.ClientSize = new Size(520, 660);" in text
    assert "detectedKeyLabel.Size = new Size(470, 52);" in text
    assert "registryHelpLabel.Size = new Size(460, 38);" in text
    assert "mapsHelpLabel.Size = new Size(448, 48);" in text
