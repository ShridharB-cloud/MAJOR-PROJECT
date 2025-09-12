@echo off
echo Starting CYBY Security Scanner...
echo.
echo Frontend will run on: http://localhost:5173
echo Backend will run on: http://localhost:8000
echo.
echo Press Ctrl+C to stop both servers
echo.

cd /d "%~dp0"
echo Current directory: %CD%
echo.

echo Installing Python dependencies...
cd backend
pip install -r requirements.txt
cd ..

echo.
echo Starting both servers...
npm run start
