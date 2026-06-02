# dev.ps1
# Runs Go Core backend, Python AI server, Playwright browser crawler, and TypeScript Vite UI concurrently in background processes.

Write-Host "Syncing and starting LastResort Local Development Environment..." -ForegroundColor Cyan

# 1. Start Playwright Browser Crawler Service in a separate window
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "cd browser; npm start" -Title "LastResort - Browser Crawler Service"
Write-Host "• Started Playwright Browser Crawler Service on port 3010" -ForegroundColor Green

# 2. Start Python AI Service in a separate window
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "& 'ai/.venv/Scripts/python.exe' 'ai/src/server.py'" -Title "LastResort - Python AI Service"
Write-Host "• Started Python AI Service on gRPC port 50052" -ForegroundColor Green

# 3. Start Go Core Backend in a separate window
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "go run cmd/lastresort/main.go serve" -Title "LastResort - Go Core Backend"
Write-Host "• Started Go Core Backend on ConnectRPC port 8443" -ForegroundColor Green

# 4. Start Vite React UI in a separate window
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "cd ui; npm run dev" -Title "LastResort - React UI"
Write-Host "• Started Vite React UI dev server on http://localhost:5173" -ForegroundColor Green

Write-Host "`nAll four processes launched in separate terminal windows! Monitor logs and press CTRL+C inside the respective terminals to stop services." -ForegroundColor Yellow
