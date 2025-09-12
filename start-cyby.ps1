Write-Host "Starting CYBY Security Scanner..." -ForegroundColor Green
Write-Host ""
Write-Host "Frontend will run on: http://localhost:5173" -ForegroundColor Cyan
Write-Host "Backend will run on: http://localhost:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop both servers" -ForegroundColor Yellow
Write-Host ""

Set-Location $PSScriptRoot
npm run start
