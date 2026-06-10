# ISMS\stop_isms.ps1
$ErrorActionPreference = "SilentlyContinue"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$runtimeDir = Join-Path $root "runtime"

function Show-Step($activity, $status, $percent) {
  $barWidth = 30
  $filled = [Math]::Floor(($percent / 100) * $barWidth)
  $empty = $barWidth - $filled
  $bar = ("█" * $filled) + ("░" * $empty)

  Write-Host ("[{0,3}%] [{1}] {2}" -f $percent, $bar, $status) -ForegroundColor Red
}

function Kill-PidFile($name) {
  $pidFile = Join-Path $runtimeDir "$name.pid"

  if (Test-Path $pidFile) {
    $pidValue = Get-Content $pidFile | Select-Object -First 1

    if ($pidValue -match "^\d+$") {
      Write-Host "     stopping $name PID $pidValue"
      taskkill /PID $pidValue /T /F | Out-Null
    }

    Remove-Item $pidFile -Force
  }
}

function Kill-Port($port) {
  $lines = netstat -aon | findstr ":$port" | findstr "LISTENING"

  foreach ($line in $lines) {
    $parts = $line -split "\s+"
    $pidValue = $parts[-1]

    if ($pidValue -match "^\d+$") {
      Write-Host "     stopping process on port $port PID $pidValue"
      taskkill /PID $pidValue /T /F | Out-Null
    }
  }
}

function Kill-ByCmdLike($pattern) {
  Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -and ($_.CommandLine -like $pattern) } |
    ForEach-Object {
      Write-Host "     stopping PID $($_.ProcessId)"
      taskkill /PID $_.ProcessId /T /F | Out-Null
    }
}

function Close-TraXusBrowserWindow {
  $profilePath = Join-Path $runtimeDir "browser-profile"

  Get-CimInstance Win32_Process |
    Where-Object {
      $_.CommandLine -and
      (
        $_.CommandLine -like "*--app=http://localhost:5173*" -or
        $_.CommandLine -like "*--app=http://127.0.0.1:5173*" -or
        $_.CommandLine -like "*$profilePath*"
      )
    } |
    ForEach-Object {
      Write-Host "     closing traXus browser window PID $($_.ProcessId)"
      taskkill /PID $_.ProcessId /T /F | Out-Null
    }
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
Write-Host "                     shutdown console" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host ""

Show-Step "Stopping traXus / ISMS" "Closing dashboard window..." 10
Close-TraXusBrowserWindow
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Stopping backend API..." 25
Kill-PidFile "backend"
Kill-Port 8000
Kill-ByCmdLike "*uvicorn*app.main:app*"
Kill-ByCmdLike "*python*uvicorn*app.main:app*"
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Stopping frontend dashboard..." 40
Kill-PidFile "frontend"
Kill-Port 5173
Kill-ByCmdLike "*node*vite*"
Kill-ByCmdLike "*npm*run*dev*"
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Stopping Windows event collector..." 55
Kill-PidFile "collector"
Kill-ByCmdLike "*windows_event_collector.py*"
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Stopping process monitor..." 70
Kill-PidFile "process_monitor"
Kill-ByCmdLike "*app.services.process_monitor*"
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Stopping network monitor..." 82
Kill-PidFile "network_monitor"
Kill-ByCmdLike "*app.services.network_monitor*"
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Stopping file monitor..." 94
Kill-PidFile "file_monitor"
Kill-ByCmdLike "*app.services.file_monitor*"
Start-Sleep -Milliseconds 500

Show-Step "Stopping traXus / ISMS" "Shutdown complete." 100

Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host " traXus stopped successfully." -ForegroundColor Green
Write-Host " All backend, frontend, monitor, and dashboard processes were requested to stop."
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host ""

Start-Sleep -Seconds 2