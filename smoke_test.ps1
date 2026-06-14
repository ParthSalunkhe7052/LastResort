# smoke_test.ps1
# Verifies compilation, executes test suites, and validates the entire build stack of LastResort.

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "             LastResort Stack Smoke Test" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify Protobuf compilation
Write-Host "[1/5] Regenerating Protobuf files..." -ForegroundColor Yellow
$env:PATH += ";$env:USERPROFILE/go/bin;ui/node_modules/.bin"
if (Get-Command buf -ErrorAction SilentlyContinue) {
    buf generate proto
    Write-Host "• Protobuf generation: OK" -ForegroundColor Green
} else {
    Write-Host "• Warning: 'buf' command not found, using existing compiled files." -ForegroundColor DarkYellow
}

# 2. Compile Go backend daemon
Write-Host "`n[2/5] Compiling Go core backend..." -ForegroundColor Yellow
go build -o test_build.exe ./cmd/lastresort
Write-Host "• Go compilation: OK (test_build.exe generated)" -ForegroundColor Green

# 3. Run all backend unit tests
Write-Host "`n[3/5] Running internal package unit tests..." -ForegroundColor Yellow
go test ./internal/...
Write-Host "• Backend unit tests: OK" -ForegroundColor Green

# 4. Run standard integration tests
Write-Host "`n[4/5] Running standard integration tests..." -ForegroundColor Yellow
go test ./tests/...
Write-Host "• Integration tests: OK" -ForegroundColor Green

# 5. Compile and bundle Vite React UI
Write-Host "`n[5/5] Checking React UI compilation and build..." -ForegroundColor Yellow
Push-Location ui
npm run build
Pop-Location
Write-Host "• React UI compilation: OK" -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "          ALL SMOKE TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# Clean up
if (Test-Path test_build.exe) {
    Remove-Item test_build.exe
}
