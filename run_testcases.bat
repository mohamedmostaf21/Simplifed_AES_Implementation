@echo off
setlocal enabledelayedexpansion

set "file=testcases.txt"

for /f "tokens=1,2,3" %%a in (%file%) do (
    if "%%a"=="ENC" (
        echo %%a %%b %%c
        saes_implementation.exe %%a %%b %%c
        echo.
    ) else if "%%a"=="DEC" (
        echo %%a %%b %%c
        saes_implementation %%a %%b %%c
        echo.
    )
)

endlocal