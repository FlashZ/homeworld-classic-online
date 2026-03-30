param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [string]$Sha256,
    [string]$SigningStatus = "",
    [string]$SigningSubject = "",
    [string]$VirusTotalSummary = "",
    [string]$VirusTotalPermalink = ""
)

$ErrorActionPreference = "Stop"

$installerName = Split-Path -Leaf $InstallerPath
$content = @"
RetailWONSetup Verification
===========================

If Windows SmartScreen or Defender asks whether this file is safe, verify the download before running it.

Installer:
$installerName

Expected SHA-256:
$Sha256

PowerShell verification:
Get-FileHash .\$installerName -Algorithm SHA256

The SHA-256 reported by PowerShell must exactly match the value above.

Code signing:
"@

if ($SigningStatus -eq "signed" -and $SigningSubject) {
    $content += "`r`nSigned in CI as: $SigningSubject"
}
elseif ($SigningStatus -eq "signed") {
    $content += "`r`nSigned in CI."
}
else {
    $content += "`r`nThis build is not code-signed in CI."
}

$content += "`r`n`r`nVirusTotal:"
if ($VirusTotalSummary) {
    $content += "`r`n$VirusTotalSummary"
}
else {
    $content += "`r`nNot configured in CI."
}

if ($VirusTotalPermalink) {
    $content += "`r`n$VirusTotalPermalink"
}

$content += "`r`n`r`nIf the SHA-256 does not match, delete the file and download it again from the release page."

$directory = Split-Path -Parent $OutputPath
if ($directory) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

Set-Content -Path $OutputPath -Value $content
