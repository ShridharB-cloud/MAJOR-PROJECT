@echo off
echo Restarting CYBY Security Scanner...
echo.

echo Killing existing processes...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM node.exe 2>nul
netstat -ano | findstr :8000 | for /f "tokens=5" %%a in ('more') do taskkill /F /PID %%a 2>nul
netstat -ano | findstr :5173 | for /f "tokens=5" %%a in ('more') do taskkill /F /PID %%a 2>nul
netstat -ano | findstr :5174 | for /f "tokens=5" %%a in ('more') do taskkill /F /PID %%a 2>nul

echo.
echo Waiting 3 seconds...
timeout /t 3 /nobreak >nul

echo.
echo Starting CYBY...
cd /d "%~dp0"
npm run start
