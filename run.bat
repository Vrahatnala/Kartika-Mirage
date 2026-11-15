@echo off
cd /d "%~dp0"
start "KARTIKA-MIRAGE engine" cmd /k python mirage-engine\main.py
start "VIP gateway" cmd /k "cd vip-gateway && python vip_server.py"
echo Buka http://127.0.0.1:8000
