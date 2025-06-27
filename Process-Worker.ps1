#!/usr/bin/env pwsh
# Process-Worker.ps1
# Processes the worker template and injects build-time generated constants

param(
    [string]$TemplateFile = "cloudflare-worker.template.js",
    [string]$OutputFile = "cloudflare-worker.js",
    [string]$ConstantsFile = "Generated/build-constants.js",
    [string]$Environment = "production",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Write-BuildLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    if ($Verbose) {
        Write-Host $logMessage -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Green" })
    }
}

try {
    Write-BuildLog "Starting worker processing..."
    Write-BuildLog "Environment: $Environment"
    
    # Check if template file exists
    if (!(Test-Path $TemplateFile)) {
        throw "Template file not found: $TemplateFile"
    }
    
    # Check if constants file exists
    if (!(Test-Path $ConstantsFile)) {
        throw "Constants file not found: $ConstantsFile. Run Generate-AuthKey.ps1 first."
    }
    
    Write-BuildLog "Reading template file: $TemplateFile"
    $templateContent = Get-Content -Path $TemplateFile -Raw
    
    Write-BuildLog "Reading constants file: $ConstantsFile"
    $constantsContent = Get-Content -Path $ConstantsFile -Raw
    
    # Remove the CommonJS export from constants for browser compatibility
    $constantsContent = $constantsContent -replace "// Export for use in worker[\s\S]*$", ""
    
    # Inject the constants into the template
    $processedContent = $templateContent -replace "__BUILD_CONSTANTS_INJECTION_POINT__", $constantsContent
    
    # Inject localhost origins for preview/development builds only
    $isPreviewBuild = $Environment.ToLower() -in @("preview", "development", "dev")
    if ($isPreviewBuild) {
        Write-BuildLog "Preview build detected - injecting localhost origins"
        
        # Find the ALLOWED_ORIGINS array and inject localhost entries
        $localhostOrigins = @"
  // Local development origins (preview builds only)
  "https://localhost:5044",
  "http://localhost:5044",
"@
        
        # Insert localhost origins after the preview worker domain line
        $processedContent = $processedContent -replace `
            '(\s*// Preview worker domain\s*\n\s*"https://abuseipdb-preview\.devnomadic\.workers\.dev")', `
            "`$1,`n$localhostOrigins"
        
        Write-BuildLog "Localhost origins added for preview build"
    } else {
        Write-BuildLog "Production build - localhost origins excluded"
    }
    
    # Also update the actual AbuseIPDB API URL parameter construction
    $urlConstruction = @"
    const apiUrl = new URL(ABUSEIPDB_API_URL);
    apiUrl.searchParams.set('ipAddress', ipAddress);
    apiUrl.searchParams.set('maxAgeInDays', maxAgeInDays);
    if (verbose) {
      apiUrl.searchParams.set('verbose', '');
    }

    // Make request to AbuseIPDB API
    const abuseIPDBResponse = await fetch(apiUrl.toString(), {
"@
    
    # Replace the fetch call with proper URL construction
    $processedContent = $processedContent -replace "// Make request to AbuseIPDB API[\s\S]*?const abuseIPDBResponse = await fetch\(ABUSEIPDB_API_URL, \{", $urlConstruction
    
    Write-BuildLog "Writing processed worker to: $OutputFile"
    $processedContent | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
    
    # Validate the generated JavaScript
    Write-BuildLog "Validating generated JavaScript..."
    
    # Check for syntax errors using Node.js if available
    $nodeCheck = Get-Command "node" -ErrorAction SilentlyContinue
    if ($nodeCheck) {
        $syntaxCheck = & node -c $OutputFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-BuildLog "JavaScript syntax validation passed"
        } else {
            throw "JavaScript syntax error: $syntaxCheck"
        }
    } else {
        Write-BuildLog "Node.js not found, skipping syntax validation" "WARN"
    }
    
    # Get file sizes for logging
    $templateSize = (Get-Item $TemplateFile).Length
    $outputSize = (Get-Item $OutputFile).Length
    
    Write-BuildLog "Worker processing completed successfully"
    Write-BuildLog "Template size: $templateSize bytes"
    Write-BuildLog "Output size: $outputSize bytes"
    
    # Output information for build systems
    if ($env:GITHUB_ACTIONS -eq "true") {
        "worker-file=$OutputFile" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding UTF8
        "worker-size=$outputSize" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding UTF8
    }
    
    exit 0
}
catch {
    Write-BuildLog "Error processing worker: $($_.Exception.Message)" "ERROR"
    Write-BuildLog "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
