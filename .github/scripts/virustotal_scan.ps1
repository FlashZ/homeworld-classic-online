param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [string]$ApiKey = $env:VIRUSTOTAL_API_KEY,
    [string]$OutputJsonPath = ""
)

$ErrorActionPreference = "Stop"

function Set-ActionOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($env:GITHUB_OUTPUT) {
        "$Name=$Value" >> $env:GITHUB_OUTPUT
    }
}

function Write-ResultFile {
    param(
        [Parameter(Mandatory = $true)]
        $Object
    )

    if (-not $OutputJsonPath) {
        return
    }

    $directory = Split-Path -Parent $OutputJsonPath
    if ($directory) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }

    $Object | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputJsonPath
}

function Invoke-VTRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Get", "Post")]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [hashtable]$Form
    )

    $headers = @{
        "accept"   = "application/json"
        "x-apikey" = $ApiKey
    }

    if ($Method -eq "Post" -and $Form) {
        return Invoke-RestMethod -Method Post -Uri $Uri -Headers $headers -Form $Form
    }

    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
}

try {
    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Installer file not found: $FilePath"
    }

    $sha256 = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $permalink = "https://www.virustotal.com/gui/file/$sha256/detection"

    Set-ActionOutput -Name "enabled" -Value "true"
    Set-ActionOutput -Name "sha256" -Value $sha256
    Set-ActionOutput -Name "permalink" -Value $permalink

    if (-not $ApiKey) {
        Set-ActionOutput -Name "status" -Value "skipped"
        Set-ActionOutput -Name "summary" -Value "VirusTotal scan skipped because VIRUSTOTAL_API_KEY is not configured."
        Write-ResultFile -Object @{
            status   = "skipped"
            sha256   = $sha256
            permalink = $permalink
        }
        return
    }

    $report = $null
    $source = "existing"

    try {
        $report = Invoke-VTRequest -Method Get -Uri "https://www.virustotal.com/api/v3/files/$sha256"
    }
    catch {
        $response = $_.Exception.Response
        $statusCode = if ($response) { [int]$response.StatusCode } else { 0 }
        if ($statusCode -ne 404) {
            throw
        }
    }

    if (-not $report) {
        $source = "uploaded"
        $upload = Invoke-VTRequest -Method Post -Uri "https://www.virustotal.com/api/v3/files" -Form @{
            file = Get-Item -LiteralPath $FilePath
        }
        $analysisId = $upload.data.id

        for ($attempt = 1; $attempt -le 8; $attempt++) {
            Start-Sleep -Seconds 20
            $analysis = Invoke-VTRequest -Method Get -Uri "https://www.virustotal.com/api/v3/analyses/$analysisId"
            if ($analysis.data.attributes.status -eq "completed") {
                break
            }
        }

        $report = Invoke-VTRequest -Method Get -Uri "https://www.virustotal.com/api/v3/files/$sha256"
    }

    $attributes = $report.data.attributes
    $stats = $attributes.last_analysis_stats
    $results = $attributes.last_analysis_results

    $malicious = [int]($stats.malicious | ForEach-Object { $_ })
    $suspicious = [int]($stats.suspicious | ForEach-Object { $_ })
    $harmless = [int]($stats.harmless | ForEach-Object { $_ })
    $undetected = [int]($stats.undetected | ForEach-Object { $_ })
    $timeout = [int]($stats.timeout | ForEach-Object { $_ })

    $flagged = @()
    if ($results) {
        foreach ($entry in $results.PSObject.Properties) {
            $category = [string]$entry.Value.category
            if ($category -in @("malicious", "suspicious")) {
                $flagged += [string]$entry.Name
            }
        }
    }

    $flaggedSummary = ($flagged | Select-Object -First 8) -join ", "
    $status = if (($malicious + $suspicious) -gt 0) { "flagged" } else { "clean" }
    $summary = "source=$source malicious=$malicious suspicious=$suspicious harmless=$harmless undetected=$undetected timeout=$timeout"

    Set-ActionOutput -Name "status" -Value $status
    Set-ActionOutput -Name "summary" -Value $summary
    Set-ActionOutput -Name "malicious" -Value "$malicious"
    Set-ActionOutput -Name "suspicious" -Value "$suspicious"
    Set-ActionOutput -Name "harmless" -Value "$harmless"
    Set-ActionOutput -Name "undetected" -Value "$undetected"
    Set-ActionOutput -Name "timeout" -Value "$timeout"
    Set-ActionOutput -Name "flagged_engines" -Value $flaggedSummary

    Write-ResultFile -Object @{
        status          = $status
        summary         = $summary
        sha256          = $sha256
        permalink       = $permalink
        source          = $source
        flagged_engines = $flagged
        report          = $report
    }
}
catch {
    $message = $_.Exception.Message -replace "\r?\n", " "
    Set-ActionOutput -Name "status" -Value "error"
    Set-ActionOutput -Name "summary" -Value "VirusTotal check failed: $message"
    Write-ResultFile -Object @{
        status    = "error"
        error     = $message
        file_path = $FilePath
    }
    throw
}
