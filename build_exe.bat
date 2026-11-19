@echo off
REM Builds RansomGuard.exe (double-click this file, or run it in Command Prompt from this folder).
REM Needs Python from python.org. Result: dist\RansomGuard\RansomGuard.exe  (zip the whole dist\RansomGuard folder to share it)
echo Installing build tools...
py -m pip install -r requirements.txt pyinstaller || goto :fail
echo Building (takes 1-3 minutes)...
py -m PyInstaller --noconfirm --clean --windowed --name RansomGuard ^
  --add-data "queries.sql;." ^
  --collect-submodules ransomguard ^
  RansomGuard.pyw || goto :fail
echo.
echo DONE. Run: dist\RansomGuard\RansomGuard.exe
pause
exit /b 0
:fail
echo.
echo BUILD FAILED - read the message above and send it to your teammate or Claude.
pause
exit /b 1
