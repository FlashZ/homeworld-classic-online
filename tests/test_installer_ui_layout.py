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


def test_install_summary_uses_compact_status_text() -> None:
    text = INSTALLER.read_text(encoding="utf-8")

    assert 'summary.Append("Writes NetTweak.script and kver.kp; CD key setup is optional.");' in text
    assert 'summary.Append("Installer key detected; a new random key will be used.");' in text


def test_install_dialog_displays_project_attribution() -> None:
    text = INSTALLER.read_text(encoding="utf-8")

    assert 'attributionLabel.Text = "Created by Nick Kerr-Bell (Zero|SF)"' in text
    assert 'contactLabel.Text = "nick@kerrbell.dev"' in text
    assert "form.Controls.Add(attributionLabel);" in text
    assert "form.Controls.Add(contactLabel);" in text
