#!/usr/bin/env pwsh
# Generate-AuthKey.ps1
# Generates a secure authentication key for build-time injection

param(
    [string]$OutputPath = ".",
    [string]$KeyLength = "32",
    [string]$Environment = "production",
    [switch]$Verbose
)

# Ensure we're using cross-platform PowerShell features
$ErrorActionPreference = "Stop"

function Write-BuildLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Verbose) {
        Write-Host $logMessage -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Green" })
    } else {
        Write-Host $logMessage
    }
}

try {
    Write-BuildLog "Starting authentication key generation process"
    Write-BuildLog "Environment: $Environment"
    
    # Determine worker URL based on environment
    $workerUrl = switch ($Environment.ToLower()) {
        "preview" { "https://abuseipdb-preview.devnomadic.workers.dev/" }
        "development" { "https://abuseipdb-preview.devnomadic.workers.dev/" }
        "dev" { "https://abuseipdb-preview.devnomadic.workers.dev/" }
        default { "https://abuseipdb.devnomadic.workers.dev/" }
    }
    
    Write-BuildLog "Worker URL: $workerUrl"
    
    # Generate a cryptographically secure random key as a UTF-8 compatible string
    $keyBytes = New-Object byte[] $KeyLength
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($keyBytes)
    
    # Convert to a Base64 string that can be safely converted back to UTF-8
    $randomBase64 = [System.Convert]::ToBase64String($keyBytes)
    
    # Create a UTF-8 compatible key string (use first 32 chars of Base64 for consistency)
    $authKeyString = $randomBase64.Substring(0, [Math]::Min(32, $randomBase64.Length)).Replace("/", "_").Replace("+", "-")
    
    # Convert the UTF-8 string to base64 for storage
    $authKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($authKeyString)
    $authKey = [System.Convert]::ToBase64String($authKeyBytes)
    
    # Create a more readable version for logging (first 8 chars + ...)
    $keyPreview = $authKey.Substring(0, 8) + "..."
    Write-BuildLog "Generated authentication key: $keyPreview"
    
    # Create output directory if it doesn't exist
    # OutputPath is expected to be the target directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-BuildLog "Created output directory: $OutputPath"
    }
    
    # Generate build timestamp
    $buildTimestamp = Get-Date -Format "yyyyMMdd-HHmm"
    $buildGuid = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    
    # Create the generated constants file for C#
    $csharpContent = @"
// <auto-generated />
// Generated at build time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
// Do not modify this file directly

namespace Albatross.Generated
{
    /// <summary>
    /// Build-time generated authentication constants
    /// </summary>
    public static class BuildConstants
    {
        /// <summary>
        /// Base64-encoded authentication key generated at build time
        /// </summary>
        public const string AuthKeyBase64 = "$authKey";
        
        /// <summary>
        /// Build timestamp
        /// </summary>
        public const string BuildTimestamp = "$buildTimestamp";
        
        /// <summary>
        /// Unique build identifier
        /// </summary>
        public const string BuildId = "$buildGuid";
        
        /// <summary>
        /// Build environment
        /// </summary>
        public const string Environment = "$Environment";
        
        /// <summary>
        /// Worker URL for this environment
        /// </summary>
        public const string WorkerUrl = "$workerUrl";
        
        /// <summary>
        /// Decoded authentication key (computed at runtime)
        /// </summary>
        public static string AuthKey => System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(AuthKeyBase64));
    }
}
"@

    # Write C# constants file
    $csharpPath = Join-Path $OutputPath "BuildConstants.cs"
    $csharpContent | Out-File -FilePath $csharpPath -Encoding UTF8
    Write-BuildLog "Generated C# constants file: $csharpPath"
    
    # Create the JavaScript constants for the worker
    $jsContent = @"
// <auto-generated />
// Generated at build time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
// Do not modify this file directly

// Build-time generated authentication key (base64 encoded)
const GENERATED_AUTH_KEY_B64 = "$authKey";

// Decode the authentication key
const GENERATED_AUTH_KEY = atob(GENERATED_AUTH_KEY_B64);

// Build information
const BUILD_TIMESTAMP = "$buildTimestamp";
const BUILD_ID = "$buildGuid";

// Export for use in worker
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AUTH_KEY: GENERATED_AUTH_KEY,
        AUTH_KEY_B64: GENERATED_AUTH_KEY_B64,
        BUILD_TIMESTAMP,
        BUILD_ID
    };
}
"@

    # Write JavaScript constants file
    $jsPath = Join-Path $OutputPath "build-constants.js"
    $jsContent | Out-File -FilePath $jsPath -Encoding UTF8
    Write-BuildLog "Generated JavaScript constants file: $jsPath"
    
    # Create environment file for GitHub Actions
    $envContent = @"
# Build-time generated environment variables
# Generated at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
GENERATED_AUTH_KEY_B64=$authKey
BUILD_TIMESTAMP=$buildTimestamp
BUILD_ID=$buildGuid
"@

    $envPath = Join-Path $OutputPath "build.env"
    $envContent | Out-File -FilePath $envPath -Encoding UTF8
    Write-BuildLog "Generated environment file: $envPath"
    
    # Create a JSON manifest for build tools
    $manifestContent = @{
        authKey = $authKey
        buildTimestamp = $buildTimestamp
        buildId = $buildGuid
        generatedAt = (Get-Date).ToString("o")
        keyLength = $KeyLength
    } | ConvertTo-Json -Depth 2
    
    $manifestPath = Join-Path $OutputPath "build-manifest.json"
    $manifestContent | Out-File -FilePath $manifestPath -Encoding UTF8
    Write-BuildLog "Generated build manifest: $manifestPath"
    
    Write-BuildLog "Authentication key generation completed successfully"
    Write-BuildLog "Build ID: $buildGuid"
    Write-BuildLog "Timestamp: $buildTimestamp"
    
    # Output key for GitHub Actions (if running in CI)
    if ($env:GITHUB_ACTIONS -eq "true") {
        Write-Host "Setting GitHub Actions output variables..."
        "auth-key-b64=$authKey" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding UTF8
        "build-id=$buildGuid" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding UTF8
        "build-timestamp=$buildTimestamp" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding UTF8
    }
    
    exit 0
}
catch {
    Write-BuildLog "Error generating authentication key: $($_.Exception.Message)" "ERROR"
    Write-BuildLog "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
finally {
    if ($rng) {
        $rng.Dispose()
    }
}
