# export_sysmon.ps1 - Exportiert Sysmon Events als JSON (optional GZIP-komprimiert)
#
# USAGE:
#   .\export_sysmon.ps1 -StartTime "2026-01-23T14:00:00" -EndTime "2026-01-23T14:05:00" -OutputPath "C:\Temp\sysmon.json" [-Compress]

param(
    [Parameter(Mandatory=$false)][string]$StartTime,
    [Parameter(Mandatory=$false)][string]$EndTime,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$false)][switch]$Compress
)

if ($StartTime) {
    $Start = [DateTime]::Parse($StartTime).AddSeconds(-5)
} else {
    $Start = (Get-Date).AddMinutes(-5)
}
if ($EndTime) {
    $End = [DateTime]::Parse($EndTime).AddSeconds(10)
} else {
    $End = Get-Date
}

Write-Host "Exportiere Sysmon Events von $Start bis $End..."
Write-Host "Aktuelle VM-Zeit: $(Get-Date -Format o)"

$DataRegex = [regex]::new('<Data Name=[''"]([^''"]+)[''"]>([^<]*)</Data>', [System.Text.RegularExpressions.RegexOptions]::Compiled)

$ParsedEvents = [System.Collections.Generic.List[object]]::new()

# Sysmon Events
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Sysmon/Operational'
        StartTime = $Start
        EndTime   = $End
    } -ErrorAction Stop

    Write-Host "Sysmon Events: $($Events.Count)"
    if ($Events.Count -gt 3000) {
        Write-Host "Events gekuerzt: $($Events.Count) -> 3000"
        $Events = $Events | Select-Object -First 3000
    }

    foreach ($Event in $Events) {
        $xml_str = $Event.ToXml()
        $EventData = [ordered]@{}
        foreach ($m in $DataRegex.Matches($xml_str)) {
            $EventData[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        $ParsedEvents.Add([PSCustomObject]@{
            EventId      = $Event.Id
            TimeCreated  = $Event.TimeCreated.ToString("o")
            ProviderName = $Event.ProviderName
            Level        = $Event.Level
            Task         = $Event.Task
            EventData    = $EventData
        })
    }
} catch {
    if ($_.Exception.Message -notmatch "No events were found") {
        Write-Warning "Sysmon Fehler: $_"
    }
}

# PowerShell ScriptBlock Events (4104)
try {
    $SbEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $Start
        EndTime   = $End
    } -ErrorAction SilentlyContinue

    Write-Host "ScriptBlock Events: $($SbEvents.Count)"

    foreach ($Event in $SbEvents) {
        $xml_str = $Event.ToXml()
        $EventData = [ordered]@{}
        foreach ($m in $DataRegex.Matches($xml_str)) {
            $v = $m.Groups[2].Value
            if ($v.Length -gt 10000) { $v = $v.Substring(0, 10000) + "... [TRUNCATED]" }
            $EventData[$m.Groups[1].Value] = $v
        }
        $ParsedEvents.Add([PSCustomObject]@{
            EventId      = 4104
            EventType    = "ScriptBlockLogging"
            TimeCreated  = $Event.TimeCreated.ToString("o")
            ProviderName = "Microsoft-Windows-PowerShell"
            EventData    = $EventData
        })
    }
} catch {}

Write-Host "Total Events: $($ParsedEvents.Count)"

# JSON schreiben
try {
    $OutputDir = Split-Path -Parent $OutputPath
    if ($OutputDir -and -not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $JsonContent = ConvertTo-Json -InputObject @($ParsedEvents) -Depth 6 -Compress
    if (-not $JsonContent) { $JsonContent = "[]" }

    $JsonBytes = [System.Text.Encoding]::UTF8.GetBytes($JsonContent)

    if ($Compress) {
        # GZIP komprimieren - 10-15x kleiner, deutlich schnellerer WinRM-Transfer
        $GzPath = $OutputPath + ".gz"
        $ms = New-Object System.IO.MemoryStream
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
        $gz.Write($JsonBytes, 0, $JsonBytes.Length)
        $gz.Close()
        [System.IO.File]::WriteAllBytes($GzPath, $ms.ToArray())
        Write-Host "Gespeichert (GZIP): $GzPath ($((Get-Item $GzPath).Length) Bytes, original $($JsonBytes.Length) Bytes)"
    } else {
        $enc = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($OutputPath, $JsonContent, $enc)
        Write-Host "Gespeichert: $OutputPath ($((Get-Item $OutputPath).Length) Bytes)"
    }
} catch {
    Write-Error "Fehler beim Speichern: $_"
    exit 1
}

exit 0
