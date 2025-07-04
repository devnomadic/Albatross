# Albatross

A modern Blazor WebAssembly application that provides comprehensive IP address analysis and abuse checking functionality. Albatross combines cloud IP range detection with AbuseIPDB reputation checking through a secure Cloudflare Worker proxy.

## Features

- **IP Abuse Checking**: Query the AbuseIPDB API to check if an IP address has been reported for malicious activity
- **Cloud IP Range Detection**: Identify if an IP address belongs to major cloud providers (AWS, Azure, GCP, Oracle Cloud)
- **Flexible Input Format**: Support for IP addresses with custom report age (e.g., `8.8.8.8;60` for 60 days of history)
- **Combined Data Sources**: Integrated AbuseIPDB and Cloudflare Radar API data for comprehensive IP analysis
- **Secure Authentication**: Build-time generated HMAC authentication with timestamp validation for enhanced security
- **CORS Protection**: Cloudflare Worker proxy handles CORS and protects API keys from client exposure
- **Modern UI**: Clean, responsive Blazor WebAssembly interface with real-time JSON formatting
- **Cross-Platform**: Runs on Windows, macOS, and Linux

## Security Architecture

This application implements a multi-layered security system with the following components:

### Build-Time Key Generation
- **Cryptographically Secure Keys**: Each build generates a unique 256-bit authentication key using `RNGCryptoServiceProvider`
- **HMAC Authentication**: Uses HMAC-SHA256 for request authentication between the Blazor app and Cloudflare Worker
- **Timestamp Validation**: 2-minute window validation to prevent replay attacks
- **No Hardcoded Secrets**: Authentication keys are generated at build time and never stored in source code

### Authentication Flow
1. **Build Process**: Generates unique authentication key and injects it into both C# and JavaScript code
2. **Client Request**: Blazor app creates HMAC token using the generated key, full request URL, and UTC timestamp
3. **Timestamp Check**: Worker validates that the request timestamp is within 2 minutes of current UTC time
4. **HMAC Validation**: Cloudflare Worker validates the HMAC token using the same generated key and full URL
5. **Origin Validation**: Additional CORS and origin checking for browser-based requests
6. **API Proxy**: Upon successful authentication, worker proxies the request to external APIs

## Build System

The project uses MSBuild targets for automated key generation and code injection:

### Pre-Build Process
1. **Key Generation** (`GenerateAuthKey` target):
   - Runs `Generate-AuthKey.ps1` PowerShell script
   - Generates cryptographically secure 256-bit key
   - Creates multiple output formats (C#, JavaScript, environment files, JSON)

2. **Worker Processing** (`ProcessWorker` target):
   - Runs `Process-Worker.ps1` PowerShell script
   - Injects generated constants into `cloudflare-worker.template.js`
   - Outputs final `cloudflare-worker.js` with embedded authentication

### Generated Files
- `Generated/BuildConstants.cs` - C# constants for the Blazor app
- `Generated/build-constants.js` - JavaScript constants for worker injection
- `Generated/build.env` - Environment file format
- `Generated/build-manifest.json` - Build metadata and timestamps
- `cloudflare-worker.js` - Final worker with injected authentication

## Setup and Development

### Prerequisites
- .NET 8.0 SDK
- Node.js 20.0.0 or higher (required for Cloudflare Wrangler 4)
- PowerShell (cross-platform)
- AbuseIPDB API key
- Cloudflare Workers account (for deployment)

### Local Development
1. Clone the repository
2. Update `cloudflare-worker.template.js` with your AbuseIPDB API key
3. Build the project: `dotnet build`
4. Run the application: `dotnet run`

### Deployment

The project uses automated GitHub Actions workflows for deployment:

**Development/Preview Deployments:**
- **Trigger**: Feature branches (`feature/*`, `fix/*`) and Pull Requests
- **SPA**: Deployed to Cloudflare Pages preview environment
- **Worker**: Deployed to static preview worker (`abuseipdb-preview`)
- **URLs**: 
  - Worker: `https://abuseipdb-preview.devnomadic.workers.dev` (static for all previews)
  - SPA: `https://{preview-name}.{project}.pages.dev`

**Production Deployments:**
- **Trigger**: Pushes to `main` branch
- **SPA**: Deployed to main Cloudflare Pages project
- **Worker**: Deployed to `abuseipdb` worker (production)
- **URL**: `https://abuseipdb.devnomadic.workers.dev`

**Manual Deployment Options:**
1. **Build Locally**: Run `dotnet build` to generate authentication keys
2. **Deploy Worker**: Upload `cloudflare-worker.js` to your Cloudflare Workers account
3. **Update Endpoint**: Configure the worker URL in `AbuseIPDBService.cs`
4. **Deploy App**: Use your preferred hosting platform

### GitHub Actions
The project includes two main deployment workflows in `.github/workflows/`:
- **`deploy-dev.yml`**: Handles development and preview deployments
- **`deploy-production.yml`**: Handles production deployments
- **`ci.yml`**: Runs tests and code formatting checks

These workflows automatically:
- Generate authentication keys during CI/CD
- Build and deploy the Blazor WebAssembly app to Cloudflare Pages
- Process and deploy the Cloudflare Worker to static preview or production workers
- Create preview environments for feature branches and PRs
- Maintain a shared `abuseipdb-preview` worker for all development deployments

## Project Structure

```
Albatross/
├── Services/
│   └── AbuseIPDBService.cs          # Main service with HMAC authentication and flexible IP parsing
├── Pages/
│   └── Home.razor                   # IP checking interface with combined functionality
├── Layout/
│   ├── MainLayout.razor             # Application layout
│   └── NavMenu.razor                # Navigation menu
├── Generated/                       # Auto-generated build artifacts
│   ├── BuildConstants.cs            # C# authentication constants
│   ├── build-constants.js           # JavaScript constants
│   ├── build.env                    # Environment variables
│   └── build-manifest.json          # Build metadata
├── .github/workflows/               # CI/CD pipelines
│   ├── ci.yml                       # Continuous integration
│   ├── deploy-dev.yml               # Development deployment
│   ├── deploy-production.yml        # Production deployment
│   ├── codeql.yml                   # GitHub Advanced Security
│   ├── dependency-review.yml        # Dependency security scanning
│   └── security-scan.yml            # Additional security checks
├── Generate-AuthKey.ps1             # PowerShell key generation script
├── Process-Worker.ps1               # Worker template processing script
├── cloudflare-worker.template.js    # Worker template with injection points
├── cloudflare-worker.js             # Generated worker with authentication (temporary)
├── SECURITY.md                      # Security policy and guidelines
└── Albatross.csproj                # MSBuild configuration with custom targets
```

## Configuration

## Configuration

### GitHub Actions Deployment

The project uses unified GitHub Actions workflows that build and deploy both the SPA and Worker together:

- **Development/Preview**: `.github/workflows/deploy-dev.yml` - Deploys to staging environments on feature branches and PRs
- **Production**: `.github/workflows/deploy-production.yml` - Deploys to production environment on main branch

**Worker Environments:**
- **Production**: `abuseipdb` worker with `production` environment
- **Preview**: `abuseipdb` worker with `preview` environment
- **Same URL**: `https://abuseipdb.devnomadic.workers.dev` for both (differentiated by environment variables)

**SPA Environments:**
- **Production**: Main Cloudflare Pages project (deployed from main branch)
- **Preview**: Branch-specific preview URLs (deployed from feature branches and PRs)

### GitHub Secrets
Configure these secrets in your repository settings (Settings → Secrets and variables → Actions):

**Required for Cloudflare Deployment:**
- `CLOUDFLARE_API_TOKEN` - Custom Cloudflare API token with Workers and Pages permissions
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID  
- `CLOUDFLARE_PAGES_PROJECT` - Your Cloudflare Pages project name (e.g., `abuseipdb-spa`)

**Required for Worker Deployment:**
- `ABUSEIPDB_API_KEY` - Your production API key from [AbuseIPDB](https://www.abuseipdb.com/)
- `ABUSEIPDB_API_KEY_DEV` - Your development API key from [AbuseIPDB](https://www.abuseipdb.com/)

### Local Development
For local development, update the fallback API key in `cloudflare-worker.template.js` or set up environment variables.

### Allowed Origins
Configure the `ALLOWED_ORIGINS` array in the worker template to specify which domains can access your API proxy.

### Worker URL
Update the `BaseUrl` in `AbuseIPDBService.cs` with your deployed Cloudflare Worker URL.

## Security Notes

- **Key Rotation**: Authentication keys are regenerated with each build, providing automatic key rotation
- **Request Validation**: All requests are validated using HMAC-SHA256 authentication with full URL signing
- **Timestamp Validation**: 2-minute window validation prevents replay attacks and ensures request freshness
- **Origin Control**: CORS headers restrict access to configured allowed origins
- **Browser-Only Access**: Worker validates User-Agent headers to ensure requests come from legitimate browsers
- **Production Origins Only**: Localhost and development origins are blocked in production deployments
- **API Key Protection**: External API keys (AbuseIPDB, Cloudflare Radar) are never exposed to client-side code
- **Multi-Layer Authentication**: HMAC authentication, timestamp validation, and origin validation must all pass
- **Input Validation**: All IP addresses are validated for proper format and public routability
- **GitHub Advanced Security**: CodeQL analysis, dependency scanning, and security workflows enabled

## Advanced Features

### Flexible Input Format
Users can specify custom report age limits using a semicolon delimiter:
- `8.8.8.8` - Uses default 30 days
- `8.8.8.8;60` - Uses 60 days of report history
- `2001:4860:4860::8888;90` - IPv6 with 90 days

### Combined API Integration
- **AbuseIPDB**: IP reputation and abuse reports
- **Cloudflare Radar**: ASN information and network details
- **Parallel Processing**: Both APIs are queried simultaneously for optimal performance
- **Graceful Degradation**: Partial results if one API fails

## Current Status

✅ **Authentication System**: Fully implemented and working
✅ **CORS Security**: Browser-only validation enabled  
✅ **Production Deployment**: Live at `https://albatross.devnomadic.com`
✅ **Build System**: Automated key generation and injection working
✅ **GitHub Actions**: Automated CI/CD pipeline functional

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all builds pass with the new authentication system
5. Submit a pull request
