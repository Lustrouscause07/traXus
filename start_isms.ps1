# ISMS\start_isms.ps1
$ErrorActionPreference = "Continue"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$backendDir  = Join-Path $root "Backend"
$frontendDir = Join-Path $root "Frontend"
$scriptsDir  = Join-Path $root "Scripts"
$runtimeDir  = Join-Path $root "runtime"
$logsDir     = Join-Path $root "logs"

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

function Show-Step($activity, $status, $percent) {
  $barWidth = 30
  $filled = [Math]::Floor(($percent / 100) * $barWidth)
  $empty = $barWidth - $filled
  $bar = ("█" * $filled) + ("░" * $empty)

  Write-Host ("[{0,3}%] [{1}] {2}" -f $percent, $bar, $status) -ForegroundColor Cyan
}

function Save-Pid($name, $processIdValue) {
  Set-Content -Path (Join-Path $runtimeDir "$name.pid") -Value $processIdValue
}

function Start-VisibleService($name, $workingDir, $command) {
  $logFile = Join-Path $logsDir "$name.log"

  $wrappedCommand = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$workingDir'
$command *>> '$logFile'
"@

  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-WindowStyle", "Hidden",
    "-Command", $wrappedCommand
  )

  $p = Start-Process powershell `
    -WorkingDirectory $workingDir `
    -WindowStyle Hidden `
    -ArgumentList $args `
    -PassThru

  Save-Pid $name $p.Id
}

function Start-AdminService($name, $workingDir, $command) {
  $logFile = Join-Path $logsDir "$name.log"

  $wrappedCommand = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$workingDir'
$command *>> '$logFile'
"@

  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-WindowStyle", "Hidden",
    "-Command", $wrappedCommand
  )

  $p = Start-Process powershell `
    -Verb RunAs `
    -WorkingDirectory $workingDir `
    -WindowStyle Hidden `
    -ArgumentList $args `
    -PassThru

  Save-Pid $name $p.Id
}

function Test-Url($url, $timeoutSec = 1) {
  try {
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $timeoutSec
    return ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500)
  } catch {
    return $false
  }
}

function Wait-ForUrl($url, $label, $startPercent, $endPercent, $maxWaitSec = 45) {
  $elapsed = 0

  while ($elapsed -lt $maxWaitSec) {
    $pct = [Math]::Min($endPercent, $startPercent + [int](($elapsed / $maxWaitSec) * ($endPercent - $startPercent)))
    Show-Step "Starting traXus / ISMS" "Waiting for $label..." $pct

    if (Test-Url $url 1) {
      Show-Step "Starting traXus / ISMS" "$label is ready" $endPercent
      return $true
    }

    Start-Sleep -Seconds 2
    $elapsed += 2
  }

  Show-Step "Starting traXus / ISMS" "$label did not confirm ready, continuing..." $endPercent
  return $false
}

Clear-Host
Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host "  ████████╗██████╗  █████╗ ██╗  ██╗██╗   ██╗███████╗" -ForegroundColor White
Write-Host "  ╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝██║   ██║██╔════╝" -ForegroundColor White
Write-Host "     ██║   ██████╔╝███████║ ╚███╔╝ ██║   ██║███████╗" -ForegroundColor White
Write-Host "     ██║   ██╔══██╗██╔══██║ ██╔██╗ ██║   ██║╚════██║" -ForegroundColor White
Write-Host "     ██║   ██║  ██║██║  ██║██╔╝ ██╗╚██████╔╝███████║" -ForegroundColor White
Write-Host "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝" -ForegroundColor White
Write-Host ""
Write-Host "                 because sus never sleeps." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host ""

Show-Step "Starting traXus / ISMS" "Preparing folders..." 5

# Backend
Show-Step "Starting traXus / ISMS" "Starting backend API..." 15
$backendCmd = @"
if (!(Test-Path .\.venv)) {
  python -m venv .\.venv
}
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
"@

Start-VisibleService "backend" $backendDir $backendCmd
Wait-ForUrl "http://127.0.0.1:8000/health" "Backend API" 15 35 60 | Out-Null

# Frontend
Show-Step "Starting traXus / ISMS" "Starting frontend dashboard..." 45
$frontendCmd = @"
if (!(Test-Path .\node_modules)) {
  npm install
}
npm run dev
"@

Start-VisibleService "frontend" $frontendDir $frontendCmd
Wait-ForUrl "http://localhost:5173" "Frontend dashboard" 45 60 60 | Out-Null

# Collector
Show-Step "Starting traXus / ISMS" "Starting Windows Event Collector with admin permissions..." 68
$collectorCmd = @"
Set-Location "$backendDir"
if (!(Test-Path .\.venv)) {
  python -m venv .\.venv
}
.\.venv\Scripts\Activate.ps1
Set-Location "$scriptsDir"
python windows_event_collector.py
"@

Start-AdminService "collector" $scriptsDir $collectorCmd
Start-Sleep -Seconds 2

# Process monitor
Show-Step "Starting traXus / ISMS" "Starting process monitor..." 75
$processCmd = @"
if (!(Test-Path .\.venv)) {
  python -m venv .\.venv
}
.\.venv\Scripts\Activate.ps1
python -m pip install psutil requests
python -m app.services.process_monitor
"@
Start-VisibleService "process_monitor" $backendDir $processCmd
Start-Sleep -Seconds 1

# Network monitor
Show-Step "Starting traXus / ISMS" "Starting network monitor..." 83
$networkCmd = @"
if (!(Test-Path .\.venv)) {
  python -m venv .\.venv
}
.\.venv\Scripts\Activate.ps1
python -m pip install psutil requests
python -m app.services.network_monitor
"@
Start-VisibleService "network_monitor" $backendDir $networkCmd
Start-Sleep -Seconds 1

# File monitor
Show-Step "Starting traXus / ISMS" "Starting file monitor..." 91
$fileCmd = @"
if (!(Test-Path .\.venv)) {
  python -m venv .\.venv
}
.\.venv\Scripts\Activate.ps1
python -m pip install watchdog requests
python -m app.services.file_monitor
"@
Start-VisibleService "file_monitor" $backendDir $fileCmd
Start-Sleep -Seconds 2

Show-Step "Starting traXus / ISMS" "Opening dashboard..." 100
$dashboardUrl = "http://localhost:5173"

$chromePath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
$edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"

if (Test-Path $chromePath) {
  Start-Process $chromePath "--app=$dashboardUrl --start-maximized --user-data-dir=`"$runtimeDir\browser-profile`""
} elseif (Test-Path $edgePath) {
  Start-Process $edgePath "--app=$dashboardUrl --start-maximized --user-data-dir=`"$runtimeDir\browser-profile`""
} else {
  Start-Process $dashboardUrl
}

Write-Host ""
Write-Host "==============================================="
Write-Host " traXus started successfully."
Write-Host " Dashboard: http://127.0.0.1:5173"
Write-Host " Backend:   http://127.0.0.1:8000/health"
Write-Host "==============================================="
Write-Host ""
Write-Host "You may close this launcher window now."
Write-Host "Use stop_isms.bat to stop all services."
Write-Host ""