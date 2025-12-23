# Heritage Bank - Start Both Servers
# Run this in PowerShell

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  HERITAGE BANK - DUAL SERVER STARTUP" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Kill any existing processes
Write-Host "🧹 Cleaning up existing processes..." -ForegroundColor Yellow
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Start backend server
Write-Host "🚀 Starting Backend Server on port 3001..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; node server.js" -WindowStyle Normal

# Wait for backend to start
Write-Host "⏳ Waiting for backend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Test backend
$testBackend = $false
for ($i = 0; $i -lt 5; $i++) {
    try {
        $health = Invoke-WebRequest -Uri "http://localhost:3001/api/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($health.StatusCode -eq 200) {
            $testBackend = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

if ($testBackend) {
    Write-Host "✅ Backend is responding!" -ForegroundColor Green
} else {
    Write-Host "⚠️ Backend may still be starting..." -ForegroundColor Yellow
}

# Start frontend server
Write-Host "🚀 Starting Frontend Server on port 8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; npx http-server -p 8000 --cache=-1" -WindowStyle Normal

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  SERVERS STARTED!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "🔌 Backend API:      http://localhost:3001" -ForegroundColor Cyan
Write-Host "🌐 Frontend:         http://localhost:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "🏥 Health Check:     http://localhost:3001/api/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "📝 Login:            http://localhost:8000/signin.html" -ForegroundColor Cyan
Write-Host "🆕 Register:         http://localhost:8000/open-account.html" -ForegroundColor Cyan
Write-Host "📊 Dashboard:        http://localhost:8000/dashboard.html" -ForegroundColor Cyan
Write-Host "⚙️  Settings:         http://localhost:8000/settings.html" -ForegroundColor Cyan
Write-Host "👨‍💼 Admin Panel:       http://localhost:8000/admin.html" -ForegroundColor Cyan
Write-Host ""
Write-Host "✨ Both servers are running!" -ForegroundColor Green
Write-Host "To stop: Close the PowerShell windows or Ctrl+C" -ForegroundColor Yellow
Write-Host ""
