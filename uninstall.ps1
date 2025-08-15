param(
    [string]$password,
    [string]$logDir,
    [boolean]$restart = $false,
    [string]$clientId, #Crowdstrike api key
    [string]$clientSecret, #Crowdstrike api key
    [string]$groupId #Crowdstrike statik grup adı
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

    # Network müsaitse oraya da yaz
    if ($networkLogFile) {
        try {
            Add-Content -Path $networkLogFile -Value $logMessage
        } catch {
            # Network yoksa hata bastır
        }
    }
}

function Is-CrowdStrikeInstalled {
    $service = Get-Service -Name "csagent" -ErrorAction SilentlyContinue
    return $service -ne $null
}

function Is-EsetInstalled {
    $app = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
           ForEach-Object { Get-ItemProperty $_.PSPath } |
           Where-Object { $_.DisplayName -match "^Eset" } |
           Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
    return $app
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
        Write-Log "Token alınamadığı için script durduruldu"
        exit 1
    }
}

function Get-DeviceID {
    $filter = [uri]::EscapeDataString("hostname:'$hostname'")
    Get-Token

    $deviceSearch = Invoke-RestMethod -Method Get `
        -Uri "https://api.us-2.crowdstrike.com/devices/queries/devices/v1?filter=$filter" `
        -Headers @{ "Authorization" = "Bearer $global:token" }

    if ($deviceSearch.resources.Count -eq 0) {
        Write-Log "Cihaz bulunamadı: $hostname"
        exit 1
    }

    $global:deviceId = $deviceSearch.resources[0]
    
    if (-not $global:deviceId) {
        Write-Log "DeviceID alınamadığı için script durduruldu"
        exit 1
    }
}

function Add-Group {
    $body = @{
        ids = @($groupId)
        action_parameters = @(
            @{
                name  = "filter"
                value = "device_id:'$($global:deviceId)'"
            }
        )
    }

    $response = Invoke-RestMethod -Method Post `
        -Uri "https://api.us-2.crowdstrike.com/devices/entities/host-group-actions/v1?action_name=add-hosts" `
        -Headers @{
            "Authorization" = "Bearer $global:token"
            "Content-Type"  = "application/json"
        } `
        -Body ($body | ConvertTo-Json -Depth 4 -Compress)


    if ($response.errors) {
        Write-Log "Gruba ekleme işleminde hata meydana geldi"
        Write-Log "Hata kodu: $($response.errors[0].code)"
        Write-Log "Hata mesajı: $($response.errors[0].message)"
        exit 1
    }

    Write-Log "Gruba Ekleme başarıyla sonuçlandı:" ($response | ConvertTo-Json -Depth 5)
}

function Uninstall-Product($productName, $passRequired = $true) {
    $result = [PSCustomObject]@{
        Product    = $productName
        Has_App    = $false
        Is_Removed = $false
        Error      = $null
    }

    try {
        $uninstall = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
            foreach { gp $_.PSPath } |
            ? { $_ -match $productName } |
            select UninstallString

        if ($uninstall) {
            $result.Has_App = $true

            $uninstallId = $uninstall.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
            $uninstallId = $uninstallId.Trim()
            
            if ($passRequired -and $password) {
                start-process "msiexec.exe" -arg "/X $uninstallId /qn /norestart password=$password" -Wait
            }
            else {
                start-process "msiexec.exe" -arg "/X $uninstallId /qn /norestart" -Wait
            }

            $result.Is_Removed = $true
            Write-Log "$productName başarıyla kaldırıldı."
        }
        else {

            Write-Log "$productName kaldırma için bulunamadı."
        }
    }
    catch {
        $result.Error = $_
        Write-Log "$productName kaldırılırken hata oluştu: $_"
    }

    $global:uninstallResults += $result
}

if (-not (Is-CrowdStrikeInstalled)) {
    Write-Log "CrowdStrike Falcon Sensor kurulu olmadığı için script durduruldu"
    exit 1
}

if (-not (Is-EsetInstalled)){
    Write-Log "Eset kurulu olmadığı için script durduruldu"
    exit 1
}

Get-DeviceID
Add-Group

Uninstall-Product "ESET Endpoint Security" $true
Uninstall-Product "ESET Inspect Connector" $true
Uninstall-Product "ESET Management Agent" $true

