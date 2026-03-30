@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if "%INSTALLER_VERSION%"=="" set "INSTALLER_VERSION=0.0.0-local"
if "%INSTALLER_FILE_VERSION%"=="" set "INSTALLER_FILE_VERSION=0.0.0.0"
if "%INSTALLER_ASSEMBLY_VERSION%"=="" set "INSTALLER_ASSEMBLY_VERSION=%INSTALLER_FILE_VERSION%"
if "%INSTALLER_OUTPUT_NAME%"=="" set "INSTALLER_OUTPUT_NAME=RetailWONSetup.exe"
set "INSTALLER_TITLE=%INSTALLER_OUTPUT_NAME:.exe=%"
set "ASSEMBLY_INFO=%TEMP%\RetailWONSetup.AssemblyInfo.%RANDOM%%RANDOM%.cs"

if not exist "%CSC%" (
    echo ERROR: csc.exe was not found at "%CSC%"
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%write_assembly_info.ps1" ^
  -Path "%ASSEMBLY_INFO%" ^
  -Title "%INSTALLER_TITLE%" ^
  -Product "RetailWONSetup" ^
  -AssemblyVersion "%INSTALLER_ASSEMBLY_VERSION%" ^
  -FileVersion "%INSTALLER_FILE_VERSION%" ^
  -InformationalVersion "%INSTALLER_VERSION%"

if errorlevel 1 exit /b %errorlevel%

"%CSC%" ^
  /nologo ^
  /target:winexe ^
  /out:"%SCRIPT_DIR%%INSTALLER_OUTPUT_NAME%" ^
  /win32icon:"%SCRIPT_DIR%HW.ico" ^
  /win32manifest:"%SCRIPT_DIR%hwclient_setup.manifest" ^
  /reference:System.Windows.Forms.dll ^
  /reference:System.Drawing.dll ^
  "%ASSEMBLY_INFO%" ^
  "%SCRIPT_DIR%retail_cdkey.cs" ^
  "%SCRIPT_DIR%hwclient_setup.cs"

set "BUILD_EXIT=%ERRORLEVEL%"
del "%ASSEMBLY_INFO%" >nul 2>&1

if not "%BUILD_EXIT%"=="0" exit /b %BUILD_EXIT%

echo Built "%SCRIPT_DIR%%INSTALLER_OUTPUT_NAME%" ^(version %INSTALLER_VERSION%^)
