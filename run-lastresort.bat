@echo off
setlocal EnableExtensions

cd /d "%~dp0"

set "ROOT=%CD%"
set "UI_URL=http://127.0.0.1:5173"
set "API_HEALTH=http://127.0.0.1:8443/health"

echo ============================================================
echo LastResort local development launcher
echo Root: %ROOT%
echo ============================================================
echo.

where go >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Go is not available on PATH.
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] npm is not available on PATH.
  pause
  exit /b 1
)

echo [INFO] Terminating any existing LastResort services to free up ports...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports = @(3010, 8443, 5173); foreach ($p in $ports) { $procs = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue; foreach ($proc in $procs) { if ($proc.OwningProcess -ne 0) { Stop-Process -Id $proc.OwningProcess -Force -ErrorAction SilentlyContinue } } }" >nul 2>nul
taskkill /FI "WINDOWTITLE eq LastResort - *" /T /F >nul 2>nul

if not exist "%ROOT%\ui\node_modules\vite" (
  echo [INFO] UI dependencies missing or incomplete. Installing...
  pushd "%ROOT%\ui"
  call npm install
  if errorlevel 1 (
    popd
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
  popd
)

if not exist "%ROOT%\browser\node_modules\playwright" (
  echo [INFO] Browser crawler dependencies missing or incomplete. Installing...
  pushd "%ROOT%\browser"
  call npm install
  if errorlevel 1 (
    popd
    echo [ERROR] npm install failed inside browser directory.
    pause
    exit /b 1
  )
  echo [INFO] Installing Playwright Chromium browser...
  call npx playwright install chromium
  if errorlevel 1 (
    popd
    echo [ERROR] Playwright browser installation failed.
    pause
    exit /b 1
  )
  popd
)

echo [1/3] Starting Playwright Browser Crawler service on port 3010...
start "LastResort - Browser Crawler Service" cmd /k "cd /d %ROOT%\browser && npm start"

echo [2/3] Building Go Core Backend binary...
go build -o "%ROOT%\lastresort.exe" cmd\lastresort\main.go
if errorlevel 1 (
  echo [WARN] Failed to compile Go backend. Falling back to slow 'go run'...
  start "LastResort - Go Core Backend" cmd /k "cd /d %ROOT% && go run cmd\lastresort\main.go serve"
) else (
  start "LastResort - Go Core Backend" cmd /k "cd /d %ROOT% && %ROOT%\lastresort.exe serve"
)

echo [3/3] Starting React UI on port 5173...
start "LastResort - React UI" cmd /k "cd /d %ROOT%\ui && npm run dev"

echo.
echo Waiting for services to activate (max 15 seconds)...
echo.
echo [TIP] If a window title says "Select LastResort...", press ENTER or ESC inside that window to resume it.
echo       Windows QuickEdit mode pauses execution when console content is clicked/marked.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "$urls = @{ 'Browser Crawler'='http://127.0.0.1:3010/health'; 'Go Core Backend'='%API_HEALTH%'; 'Vite React UI'='%UI_URL%' }; $start = Get-Date; $timeout = 15; while (((Get-Date) - $start).TotalSeconds -lt $timeout) { $pending = 0; foreach ($name in $urls.Keys) { try { $r = Invoke-WebRequest -UseBasicParsing -Uri $urls[$name] -TimeoutSec 1 -ErrorAction SilentlyContinue; if ($r.StatusCode -ne 200) { $pending++ } } catch { $pending++ } }; if ($pending -eq 0) { exit 0 }; Start-Sleep -Milliseconds 500 }; exit 1"

if errorlevel 1 (
  echo [WARN] Some services did not respond in time, proceeding to open the UI anyway...
) else (
  echo [OK] All services are online!
)

echo.
echo Opening LastResort UI: %UI_URL%
start "" "%UI_URL%"
echo.
echo To scan your personal website:
echo 1. Enter the full authorized URL in the Target URL field.
echo 2. Use QUICK first, then STANDARD after the first scan works.
echo.
echo Keep the three service windows open while testing.
pause
