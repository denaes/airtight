@echo off
rem airtight launcher for Windows. Mirrors scripts/airtight.
setlocal
set "DIR=%~dp0"
set "DIR=%DIR:~0,-1%"

set "ENGINE="
if defined AIRTIGHT_ENGINE if exist "%AIRTIGHT_ENGINE%" set "ENGINE=%AIRTIGHT_ENGINE%"
if not defined ENGINE if exist "%DIR%\engine\airtight.mjs" set "ENGINE=%DIR%\engine\airtight.mjs"
if not defined ENGINE if exist "%DIR%\..\..\..\engine\src\cli.mjs" set "ENGINE=%DIR%\..\..\..\engine\src\cli.mjs"

where node >nul 2>&1
if errorlevel 1 (
  if /i "%~1"=="hook" exit /b 0
  echo airtight: no Node runtime found on PATH. Install Node 20 or later. 1>&2
  exit /b 127
)
if not defined ENGINE (
  if /i "%~1"=="hook" exit /b 0
  echo airtight: engine not found next to %DIR%. Reinstall the skill. 1>&2
  exit /b 127
)

if not defined AIRTIGHT_RULES if exist "%DIR%\rules.json" set "AIRTIGHT_RULES=%DIR%\rules.json"
node "%ENGINE%" %*
