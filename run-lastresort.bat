@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

set "ROOT=%CD%"
set "UI_URL=http://127.0.0.1:5173"
set "API_HEALTH=http://127.0.0.1:8443/health"
set "BROWSER_HEALTH=http://127.0.0.1:3010/health"

echo ============================================================
echo LastResort local development launcher
echo Root: "%ROOT%"
echo ============================================================
echo.

:: 1. Dependency Checks
where go >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Go is not available on PATH. Please install Go.
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] npm is not available on PATH. Please install Node.js.
  pause
  exit /b 1
)

:: 2. Cleanup existing processes (More Aggressive)
echo [INFO] Terminating any existing LastResort services to free up ports...

:: Kill processes by port using PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ports = @(3010, 8443, 5173); ^
   foreach ($p in $ports) { ^
     $conns = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue; ^
     foreach ($c in $conns) { ^
       if ($c.OwningProcess -ne 0) { ^
         $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; ^
         if ($proc) { ^
           Write-Host \"[INFO] Killing $($proc.Name) (PID $($proc.Id)) listening on port $p\"; ^
           Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue; ^
         } ^
       } ^
     } ^
   }"

:: Kill any window with LastResort in title
taskkill /FI "WINDOWTITLE eq LastResort - *" /T /F >nul 2>&1

:: Kill by process names if they are likely ours
taskkill /IM lastresort.exe /F >nul 2>&1

echo [INFO] Waiting 2 seconds for ports to be released...
timeout /t 2 /nobreak >nul

:: 3. Install dependencies if missing
if not exist "ui\node_modules\" (
  echo [INFO] UI dependencies missing. Installing...
  pushd "ui"
  call npm install
  if errorlevel 1 (
    popd
    echo [ERROR] npm install failed in ui directory.
    pause
    exit /b 1
  )
  popd
)

if not exist "browser\node_modules\" (
  echo [INFO] Browser crawler dependencies missing. Installing...
  pushd "browser"
  call npm install
  if errorlevel 1 (
    popd
    echo [ERROR] npm install failed in browser directory.
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

:: 4. Start Services
echo [1/3] Starting Playwright Browser Crawler service on port 3010...
start "LastResort - Browser Crawler Service" cmd /k "cd /d ""%ROOT%\browser"" && npm start"

echo [2/3] Building Go Core Backend binary...
go build -o "%ROOT%\lastresort.exe" cmd\lastresort\main.go
if errorlevel 1 (
  echo [WARN] Failed to compile Go backend. Falling back to slow 'go run'...
  start "LastResort - Go Core Backend" cmd /k "cd /d ""%ROOT%"" && go run cmd\lastresort\main.go serve"
) else (
  start "LastResort - Go Core Backend" cmd /k "cd /d ""%ROOT%"" && ""%ROOT%\lastresort.exe"" serve"
)

echo [3/3] Starting React UI on port 5173...
start "LastResort - React UI" cmd /k "cd /d ""%ROOT%\ui"" && npm run dev"

echo.
echo Waiting for services to activate (max 20 seconds)...
echo.

:: 5. Health Check Wait Loop
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$urls = @{ 'Browser Crawler'='%BROWSER_HEALTH%'; 'Go Core Backend'='%API_HEALTH%'; 'Vite React UI'='%UI_URL%' }; ^
   $start = Get-Date; ^
   $timeout = 20; ^
   while (((Get-Date) - $start).TotalSeconds -lt $timeout) { ^
     $pending = 0; ^
     foreach ($name in $urls.Keys) { ^
       try { ^
         $r = Invoke-WebRequest -UseBasicParsing -Uri $urls[$name] -TimeoutSec 1 -ErrorAction SilentlyContinue; ^
         if ($r.StatusCode -ne 200) { $pending++ } ^
       } catch { $pending++ } ^
     }; ^
     if ($pending -eq 0) { exit 0 }; ^
     Start-Sleep -Milliseconds 500 ^
   }; ^
   exit 1"

if errorlevel 1 (
  echo [WARN] Some services did not respond in time. 
  echo [INFO] Check the opened terminal windows for errors.
  echo [INFO] Proceeding to open the UI anyway...
) else (
  echo [OK] All services are online!
)

echo.
echo Opening LastResort UI: %UI_URL%
start "" "%UI_URL%"
echo.
echo Keep the three service windows open while testing.
echo Press any key to exit this launcher (services will keep running).
pause >nul
