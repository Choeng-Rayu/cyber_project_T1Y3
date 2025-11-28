# ============================================================
# Victim Files Setup Script - PowerShell Version
# Creates victim files directory and test files on Drive C
# ============================================================

Write-Host "`n" -ForegroundColor Green
Write-Host "===== VICTIM FILES SETUP - Creating Files on C: =====" -ForegroundColor Green
Write-Host "`n"

# Define paths
$mainDir = "C:\MalwareLab"
$victimDir = "C:\MalwareLab\VictimFiles"

# Create main directory
if (-not (Test-Path $mainDir)) {
    New-Item -ItemType Directory -Path $mainDir -Force | Out-Null
    Write-Host "[OK] Created: $mainDir" -ForegroundColor Green
} else {
    Write-Host "[EXISTS] Exists: $mainDir" -ForegroundColor Yellow
}

# Create VictimFiles directory
if (-not (Test-Path $victimDir)) {
    New-Item -ItemType Directory -Path $victimDir -Force | Out-Null
    Write-Host "[OK] Created: $victimDir" -ForegroundColor Green
} else {
    Write-Host "[EXISTS] Exists: $victimDir" -ForegroundColor Yellow
}

# Create authorization file
$authFile = "$victimDir\ALLOW_SIMULATION.txt"
New-Item -ItemType File -Path $authFile -Force | Out-Null
Write-Host "[OK] Created: ALLOW_SIMULATION.txt" -ForegroundColor Green

# Create document1.txt
$doc1 = "Sensitive Company Data - Document 1`nUsername: admin`nPassword: secret123`nDepartment: Finance"
Set-Content -Path "$victimDir\document1.txt" -Value $doc1
Write-Host "[OK] Created: document1.txt" -ForegroundColor Green

# Create document2.txt
$doc2 = "Project Information - CONFIDENTIAL`nProject Name: Operation Alpha`nBudget: $1,000,000`nTimeline: Q1 2025"
Set-Content -Path "$victimDir\document2.txt" -Value $doc2
Write-Host "[OK] Created: document2.txt" -ForegroundColor Green

# Create data.csv
$csv = "Name,Email,Phone,Department`nJohn Smith,john@company.com,555-0001,Finance`nJane Doe,jane@company.com,555-0002,HR`nBob Johnson,bob@company.com,555-0003,IT"
Set-Content -Path "$victimDir\data.csv" -Value $csv
Write-Host "[OK] Created: data.csv" -ForegroundColor Green

# Create credentials.txt
$creds = "Database Credentials`nHost: db.company.com`nUser: admin`nPassword: P@ssw0rd123!"
Set-Content -Path "$victimDir\credentials.txt" -Value $creds
Write-Host "[OK] Created: credentials.txt" -ForegroundColor Green
