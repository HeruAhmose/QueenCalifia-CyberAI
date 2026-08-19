@echo off
setlocal
where pwsh.exe >nul 2>&1
if errorlevel 1 (
  echo PowerShell 7 ^(pwsh.exe^) is required.
  pause
  exit /b 1
)
pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0qc.ps1" activate
if errorlevel 1 (
  echo.
  echo Queen Califia activation failed. Review the error above.
  pause
  exit /b 1
)
endlocal
