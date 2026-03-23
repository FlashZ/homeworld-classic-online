@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if not exist "%CSC%" (
    echo ERROR: csc.exe was not found at "%CSC%"
    exit /b 1
)

"%CSC%" ^
  /nologo ^
  /target:winexe ^
  /out:"%SCRIPT_DIR%HWOnlineSetup.exe" ^
  /win32manifest:"%SCRIPT_DIR%hwclient_setup.manifest" ^
  /reference:System.Windows.Forms.dll ^
  /reference:System.Drawing.dll ^
  "%SCRIPT_DIR%hwclient_setup.cs"

if errorlevel 1 exit /b %errorlevel%

echo Built "%SCRIPT_DIR%HWOnlineSetup.exe"
