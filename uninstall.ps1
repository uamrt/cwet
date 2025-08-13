param(
    [string]$password,
    [string]$logDir,
    [boolean]$restart = $false
)

Set-ExecutionPolicy Bypass -Scope Process -Force

$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

$localLogFolder = "C:\Windows\Temp"
if (-not (Test-Path $localLogFolder)) {
    New-Item -Path $localLogFolder -ItemType Directory -Force | Out-Null
}
$localLogFile = Join-Path $localLogFolder "$hostname`_$timestamp.log"

# Network log yolu (opsiyonel)
if ($logDir -and (Test-Path $logDir)) {
    $networkLogFile = Join-Path $logDir "$hostname`_$timestamp.log"
} else {
    $networkLogFile = $null
}

$anyUninstalled = $false

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

function Uninstall-Product($productName, $passRequired = $true) {
    try {
        $uninstall = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
            foreach { gp $_.PSPath } |
            ? { $_ -match $productName } |
            select UninstallString

        if ($uninstall) {
            $uninstallId = $uninstall.UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
            $uninstallId = $uninstallId.Trim()
            
            if ($passRequired -and $password) {
                start-process "msiexec.exe" -arg "/X $uninstallId /qn /norestart password=$password" -Wait
            }
            else {
                start-process "msiexec.exe" -arg "/X $uninstallId /qn /norestart" -Wait
            }

            $global:anyUninstalled = $true
            Write-Log "$productName başarıyla kaldırıldı."
        }
        else {
            Write-Log "$productName kaldırma için bulunamadı."
        }
    }
    catch {
        Write-Log "$productName kaldırılırken hata oluştu: $_"
    }
}

Uninstall-Product "ESET Endpoint Security" $true
Uninstall-Product "ESET Inspect Connector" $true
Uninstall-Product "ESET Management Agent" $false

if ($anyUninstalled -and $restart) {
    Write-Log "En az bir ürün kaldırıldı, 15 dakika içinde yeniden başlatma planlandı."
    msg * "Bazı güvenlik yazılımları kaldırıldı. Bilgisayar 15 dakika içinde yeniden başlatılacaktır."
    shutdown /r /t 900 /c "Bazı güvenlik yazılımları kaldırıldı. Bilgisayar yeniden başlatılacak."
}
elseif ($anyUninstalled) {
    Write-Log "En az bir ürün kaldırıldı, yeniden başlatma yapılmayacak."
}
else {
    Write-Log "Herhangi bir ürün kaldırılmadı."
}
