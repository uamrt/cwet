param(
    [string]$password
)

Set-ExecutionPolicy Bypass -Scope Process -Force

function Uninstall-Product($productName, $passRequired = $true) {
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
        
    }
}

Uninstall-Product "ESET Endpoint Security" $true
Uninstall-Product "ESET Inspect Connector" $true
Uninstall-Product "ESET Management Agent" $false