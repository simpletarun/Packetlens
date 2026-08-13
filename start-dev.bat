@echo off
cd /d "%~dp0frontend"
echo Starting PacketLens dev server on http://localhost:3456
call npm run dev -- --port 3456
pause
