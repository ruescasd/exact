# Set error action preference to stop on errors
$ErrorActionPreference = "Stop"

# Get the directory where the script is located
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Navigate to the project root directory (assuming the script is in a subdirectory like 'scripts')
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $ProjectRoot

Write-Host "Starting WebAssembly build..."

try {    
    # Build the project using wasm-pack
    # cmd /c 'set WASM_OPT_ARGS=--enable-reference-types && wasm-pack build --target web --out-dir www/pkg --release'
    wasm-pack build --target web --out-dir www/pkg --release
    Write-Host "Build successful. Outputting to www/pkg"
    Write-Host "Contents of www/pkg:"
    Get-ChildItem -Path www/pkg | ForEach-Object { Write-Host $_.Name }
}
catch {
    Write-Error "Error during wasm-pack build: $($_.Exception.Message)"
    exit 1
}


# Write-Host "Launching index.html in the default web browser..."
# try {
#    Start-Process "www/index.html"
#    Write-Host "Successfully launched index.html."
#}
#catch {
#    Write-Error "Failed to launch index.html: $($_.Exception.Message)"
#    Write-Host "Please open www/index.html in your browser manually."
#    exit 1
#}

Write-Host "Script finished."
