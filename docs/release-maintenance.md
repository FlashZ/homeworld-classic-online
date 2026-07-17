# Release Maintenance

The installer release workflow publishes the Windows installer, Linux/Wine/Proton helper bundle, SHA-256 files, a VirusTotal report, an SPDX SBOM, and a JSON release manifest. GitHub also creates build-provenance attestations for every release asset.

## Code signing

Code signing remains optional so maintainers can still make a release without a certificate, but production releases should use it whenever a certificate is available. Add these repository secrets before dispatching the release workflow:

| Secret | Required | Purpose |
|---|---:|---|
| `WINDOWS_CODESIGN_CERT_PFX_BASE64` | Yes | Base64-encoded code-signing PFX certificate. |
| `WINDOWS_CODESIGN_CERT_PFX_PASSWORD` | Yes | Password for the PFX certificate. |
| `WINDOWS_CODESIGN_TIMESTAMP_URL` | No | RFC 3161 timestamp service; defaults to DigiCert's service. |
| `VIRUSTOTAL_API_KEY` | No | Produces a VirusTotal report for the Windows installer. |

The workflow verifies the Authenticode signature after signing and records the signing result in `VERIFY.txt` and the release notes. Do not store the PFX in the repository or in a release artifact.

## Release verification

Each release asset has a SHA-256 value in its adjacent `.sha256` file or in the release manifest. A user can verify the Windows installer with:

```powershell
Get-FileHash .\RetailWONSetup-...exe -Algorithm SHA256
```

Verify GitHub build provenance after downloading an asset with:

```bash
gh attestation verify <downloaded-file> --owner FlashZ
```

## Map-pack updates

The optional community map pack is deliberately pinned to a reviewed commit and SHA-256 in both installer implementations. When updating it, change the URL and checksum in `installer/install-linux.sh` and `installer/hwclient_setup_maps.cs`, then review and test the downloaded archive before releasing a new installer.
