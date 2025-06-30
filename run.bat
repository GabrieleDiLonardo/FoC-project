@echo off
REM Apri una finestra per il server (rimane aperta dopo l'esecuzione)
start "Server" cmd /k "bin\server.exe"

REM Aspetta 2 secondi per far partire il server
timeout /t 2 /nobreak >nul

REM Apri una finestra per il client (rimane aperta dopo l'esecuzione)
start "Client" cmd /k "bin\client.exe"
