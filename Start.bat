@echo off
cd /d "%~dp0"
start cmd /k "npm run dev"
cd /d "%~dp0\backend"
start cmd /k "node server.js"

start http://localhost:5173/
start http://localhost:5000/api-docs