@echo off
REM ============================================================
REM Victim Files Setup Script for Drive C
REM This script creates the victim files directory and test files
REM ============================================================

echo.
echo Creating Victim Files Directory...
echo.

REM Create main directory
if not exist "C:\MalwareLab" (
    mkdir "C:\MalwareLab"
    echo [OK] Created C:\MalwareLab
) else (
    echo [EXISTS] C:\MalwareLab already exists
)

REM Create VictimFiles subdirectory
if not exist "C:\MalwareLab\VictimFiles" (
    mkdir "C:\MalwareLab\VictimFiles"
    echo [OK] Created C:\MalwareLab\VictimFiles
) else (
    echo [EXISTS] C:\MalwareLab\VictimFiles already exists
)

REM Create authorization file
echo. > "C:\MalwareLab\VictimFiles\ALLOW_SIMULATION.txt"
echo [OK] Created ALLOW_SIMULATION.txt

REM Create test documents
echo Sensitive Company Data - Document 1 > "C:\MalwareLab\VictimFiles\document1.txt"
echo Username: admin >> "C:\MalwareLab\VictimFiles\document1.txt"
echo Password: secret123 >> "C:\MalwareLab\VictimFiles\document1.txt"
echo Department: Finance >> "C:\MalwareLab\VictimFiles\document1.txt"
echo [OK] Created document1.txt

echo. > "C:\MalwareLab\VictimFiles\document2.txt"
echo Project Information - CONFIDENTIAL >> "C:\MalwareLab\VictimFiles\document2.txt"
echo Project Name: Operation Alpha >> "C:\MalwareLab\VictimFiles\document2.txt"
echo Budget: $1,000,000 >> "C:\MalwareLab\VictimFiles\document2.txt"
echo Timeline: Q1 2025 >> "C:\MalwareLab\VictimFiles\document2.txt"
echo Team Lead: John Smith >> "C:\MalwareLab\VictimFiles\document2.txt"
echo [OK] Created document2.txt

echo. > "C:\MalwareLab\VictimFiles\data.csv"
echo Name,Email,Phone,Department >> "C:\MalwareLab\VictimFiles\data.csv"
echo John Smith,john.smith@company.com,555-0001,Finance >> "C:\MalwareLab\VictimFiles\data.csv"
echo Jane Doe,jane.doe@company.com,555-0002,HR >> "C:\MalwareLab\VictimFiles\data.csv"
echo Bob Johnson,bob.johnson@company.com,555-0003,IT >> "C:\MalwareLab\VictimFiles\data.csv"
echo Alice Brown,alice.brown@company.com,555-0004,Sales >> "C:\MalwareLab\VictimFiles\data.csv"
echo [OK] Created data.csv

echo. > "C:\MalwareLab\VictimFiles\credentials.txt"
echo Database Credentials >> "C:\MalwareLab\VictimFiles\credentials.txt"
echo Host: db.company.com >> "C:\MalwareLab\VictimFiles\credentials.txt"
echo User: admin >> "C:\MalwareLab\VictimFiles\credentials.txt"
echo Password: P@ssw0rd123! >> "C:\MalwareLab\VictimFiles\credentials.txt"
echo Database: company_prod >> "C:\MalwareLab\VictimFiles\credentials.txt"
echo [OK] Created credentials.txt

echo.
echo ============================================================
echo Setup Complete!
echo ============================================================
echo.
echo Victim Files Location: C:\MalwareLab\VictimFiles\
echo.
echo Files Created:
echo   - ALLOW_SIMULATION.txt (authorization file)
echo   - document1.txt (company data)
echo   - document2.txt (project info)
echo   - data.csv (employee data)
echo   - credentials.txt (database credentials)
echo.
echo Ready to run malware simulation!
echo.
pause
