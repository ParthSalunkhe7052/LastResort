@echo off
setlocal EnableExtensions

cd /d "%~dp0"

set "ROOT=%CD%"
set "AI_PY=%ROOT%\ai\.venv\Scripts\python.exe"
set "UI_URL=http://127.0.0.1:5173"
set "API_HEALTH=http://127.0.0.1:8443/health"
set "PROXY_PORT=8080"
set "AI_PORT=50052"

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

rem --- Resolve Python interpreter for AI service (prefer venv, fallback to py/python) ---
set "AI_PY_CMD="
set "AI_PY_DISPLAY="
set "AI_PY_QUOTED=0"

if exist "%ROOT%\ai\.venv\Scripts\python.exe" (
  set "AI_PY_CMD=%ROOT%\ai\.venv\Scripts\python.exe"
  set "AI_PY_DISPLAY=%ROOT%\ai\.venv\Scripts\python.exe"
  set "AI_PY_QUOTED=1"
) else (
  where py >nul 2>nul
  if not errorlevel 1 (
    set "AI_PY_CMD=py -3"
    set "AI_PY_DISPLAY=py -3"
  ) else (
    where python >nul 2>nul
    if not errorlevel 1 (
      set "AI_PY_CMD=python"
      set "AI_PY_DISPLAY=python"
    )
  )
)

if not defined AI_PY_CMD (
  echo [ERROR] Python was not found. No venv, no py launcher, and no python on PATH.
  echo Expected venv interpreter at:
  echo   %ROOT%\ai\.venv\Scripts\python.exe
  echo.
  echo Fix: create the venv under ai\.venv or install Python and ensure it is on PATH.
  pause
  exit /b 1
)

echo [INFO] AI Python interpreter: %AI_PY_DISPLAY%
rem Validate interpreter before starting a new window (prevents the "python.exe as script" failure mode)
if "%AI_PY_QUOTED%"=="1" (
  call "%AI_PY_CMD%" --version >nul 2>nul
) else (
  call %AI_PY_CMD% --version >nul 2>nul
)
if errorlevel 1 (
  echo [ERROR] AI Python interpreter failed to run: %AI_PY_DISPLAY%
  echo This usually means the venv is corrupted or the path points to a non-interpreter binary.
  pause
  exit /b 1
)

if not exist "%ROOT%\ui\node_modules" (
  echo [INFO] ui\node_modules was not found. Installing UI dependencies...
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

if not exist "%ROOT%\browser\node_modules" (
  echo [INFO] browser\node_modules was not found. Installing browser crawler dependencies...
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

echo [1/4] Starting Playwright Browser Crawler service on port 3010...
start "LastResort - Browser Crawler Service" cmd /k "cd /d "%ROOT%\browser" && npm start"

rem If 50052 is already in use on Windows, pick 50053 so AI can bind.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,%AI_PORT%); $l.Start(); $l.Stop(); exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  echo [WARN] AI gRPC port %AI_PORT% is busy. Falling back to 50053...
  set "AI_PORT=50053"
)

echo [2/4] Starting Python AI service on port 50052...
if "%AI_PY_QUOTED%"=="1" (
  start "LastResort - Python AI Service" cmd /k "cd /d "%ROOT%" && set AI_PORT=%AI_PORT% && "%AI_PY_CMD%" "%ROOT%\ai\src\server.py""
) else (
  start "LastResort - Python AI Service" cmd /k "cd /d "%ROOT%" && set AI_PORT=%AI_PORT% && %AI_PY_CMD% "%ROOT%\ai\src\server.py""
)

rem If 8080 is already in use on Windows, pick 8081 so backend doesn't hard-fail.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,%PROXY_PORT%); $l.Start(); $l.Stop(); exit 0 } catch { exit 1 }" >nul 2>nul
if errorlevel 1 (
  echo [WARN] Proxy port %PROXY_PORT% is busy. Falling back to 8081...
  set "PROXY_PORT=8081"
)

echo [3/4] Building Go Core Backend binary...
go build -o "%ROOT%\lastresort.exe" cmd\lastresort\main.go
if errorlevel 1 (
  echo [WARN] Failed to compile Go backend. Falling back to slow 'go run'...
  start "LastResort - Go Core Backend" cmd /k "cd /d "%ROOT%" && go run cmd\lastresort\main.go serve -proxy-port %PROXY_PORT% -ai-addr http://127.0.0.1:%AI_PORT%"
) else (
  start "LastResort - Go Core Backend" cmd /k "cd /d "%ROOT%" && "%ROOT%\lastresort.exe" serve -proxy-port %PROXY_PORT% -ai-addr http://127.0.0.1:%AI_PORT%"
)

echo [4/4] Starting React UI on port 5173...
start "LastResort - React UI" cmd /k "cd /d "%ROOT%\ui" && npm run dev"

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
echo 3. For proxy history, configure a browser proxy to 127.0.0.1:%PROXY_PORT%.
echo 4. Trust the local CA certificate at data\certs\ca.crt only for testing.
echo.
echo Keep the four service windows open while testing.
pause
