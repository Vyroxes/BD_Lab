@echo off
cd /d "%~dp0"
start cmd /k "npm run dev"
echo http://localhost:5173/ | clip