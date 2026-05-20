@echo off
echo Compiling all Java files...

REM Collect all .java files from all subfolders into a list
dir /s /b *.java > sources.txt

REM Compile everything at once using the list file
javac -cp "." @sources.txt

if %ERRORLEVEL% == 0 (
    echo.
    echo Compilation successful!
    echo Now run: run_all.bat
) else (
    echo.
    echo Compilation FAILED. Check errors above.
)

del sources.txt
pause
