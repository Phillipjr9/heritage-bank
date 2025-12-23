@echo off
REM Heritage Bank - Start Both Servers

echo.
echo ============================================
echo   HERITAGE BANK - DUAL SERVER STARTUP
echo ============================================
echo.

REM Kill any existing processes
echo Cleaning up existing processes...
taskkill /F /IM node.exe >nul 2>&1
timeout /t 2 /nobreak >nul

REM Start backend server in a new window
echo Starting Backend Server on port 3001...
start "Heritage Bank Backend" cmd /k "cd backend && node server.js"

REM Wait for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend server in a new window
echo Starting Frontend Server on port 8000...
start "Heritage Bank Frontend" cmd /k "npx http-server -p 8000 --cache=-1"

REM Wait for frontend to start
timeout /t 3 /nobreak >nul

echo.
echo ============================================
echo   SERVERS STARTING...
echo ============================================
echo.
echo Backend API:     http://localhost:3001
echo Frontend:        http://localhost:8000
echo.
echo Health Check:    http://localhost:3001/api/health
echo.
echo Login:           http://localhost:8000/signin.html
echo Register:        http://localhost:8000/open-account.html
echo Dashboard:       http://localhost:8000/dashboard.html
echo Admin Panel:     http://localhost:8000/admin.html
echo Settings:        http://localhost:8000/settings.html
echo.
echo Press Ctrl+C in any window to stop that server
echo.
pause
