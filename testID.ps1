param(
    [string]$password,
    [string]$logDir,
    [string]$clientId, #Crowdstrike api key
    [string]$clientSecret
)

Set-ExecutionPolicy Bypass -Scope Process -Force

$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

$token = ""
$deviceId = ""

$global:uninstallResults = @()

$localLogFile = Join-Path "C:\Windows\Temp" "$hostname`_$timestamp.log"

# Network log yolu (opsiyonel)
if ($logDir -and (Test-Path $logDir)) {
    $networkLogFile = Join-Path $logDir "$hostname`_$timestamp.log"
} else {
    $networkLogFile = $null
}

function Write-Log($message) {
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$time] $message"

    # Her zaman lokal log
    Add-Content -Path $localLogFile -Value $logMessage

    # Network mÃ¼saitse oraya da yaz
    if ($networkLogFile) {
        try {
            Add-Content -Path $networkLogFile -Value $logMessage
        } catch {
            # Network yoksa hata bastÄ±r
        }
    }
}

function Get-Token {
    $tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://api.us-2.crowdstrike.com/oauth2/token" `
    -Body @{
        client_id     = $clientId
        client_secret = $clientSecret
    } `
    -ContentType "application/x-www-form-urlencoded"

    $global:token = $tokenResponse.access_token

    if (-not $global:token) {
        Write-Log "Token alÄ±namadÄ±ÄŸÄ± iÃ§in script durduruldu"
        exit 1
    }
}

function Get-DeviceID {
    Write-Log $hostname
    $filter = [uri]::EscapeDataString("hostname:'$hostname'")

    Get-Token

    $deviceSearch = Invoke-RestMethod -Method Get `
        -Uri "https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=$filter" `
        -Headers @{ "Authorization" = "Bearer $global:token" }

    if ($deviceSearch.resources.Count -eq 0) {
        Write-Log "Cihaz bulunamadÄ±: $hostname"
        exit 1
    }

    $global:deviceId = $deviceSearch.resources[0]
    
    if (-not $global:deviceId) {
        Write-Log "DeviceID alÄ±namadÄ±ÄŸÄ± iÃ§in script durduruldu"
        exit 1
    }

    Write-Log "DeviceID: ($global:deviceId)"
}

Get-DeviceID