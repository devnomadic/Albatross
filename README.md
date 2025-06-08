# Albatross

A Blazor WebAssembly application that provides IP address abuse checking functionality using the AbuseIPDB API through a secure Cloudflare Worker proxy.

## Features

- **IP Abuse Checking**: Query the AbuseIPDB API to check if an IP address has been reported for malicious activity
- **Secure Authentication**: Build-time generated HMAC authentication keys for enhanced security
- **CORS Protection**: Cloudflare Worker proxy handles CORS and protects API keys from client exposure
- **Modern UI**: Clean, responsive Blazor WebAssembly interface
- **Cross-Platform**: Runs on Windows, macOS, and Linux

## Security Architecture

This application implements a secure authentication system with the following components:

### Build-Time Key Generation
- **Cryptographically Secure Keys**: Each build generates a unique 256-bit authentication key using `RNGCryptoServiceProvider`
- **HMAC Authentication**: Uses HMAC-SHA256 for request authentication between the Blazor app and Cloudflare Worker
- **No Hardcoded Secrets**: Authentication keys are generated at build time and never stored in source code

### Authentication Flow
1. **Build Process**: Generates unique authentication key and injects it into both C# and JavaScript code
2. **Client Request**: Blazor app creates HMAC token using the generated key and request URL
3. **Worker Validation**: Cloudflare Worker validates the HMAC token using the same generated key
4. **API Proxy**: Upon successful authentication, worker proxies the request to AbuseIPDB API

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
- **Worker**: Deployed to same `abuseipdb` worker with `preview` environment
- **URL**: Same URL `https://abuseipdb.workers.dev` but with environment differentiation

**Production Deployments:**
- **Trigger**: Pushes to `main` branch
- **SPA**: Deployed to main Cloudflare Pages project
- **Worker**: Deployed to `abuseipdb` worker with `production` environment
- **URL**: Same URL `https://abuseipdb.workers.dev` but with production environment

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
- Process and deploy the Cloudflare Worker with environment-specific API keys
- Create preview environments for feature branches and PRs

## Project Structure

```
Albatross/
├── Services/
│   └── AbuseIPDBService.cs          # Main service with HMAC authentication
├── Pages/
│   ├── Home.razor                   # IP checking interface
│   ├── Counter.razor                # Sample page
│   └── Weather.razor                # Sample page
├── Generated/                       # Auto-generated build artifacts
│   ├── BuildConstants.cs            # C# authentication constants
│   ├── build-constants.js           # JavaScript constants
│   ├── build.env                    # Environment variables
│   └── build-manifest.json          # Build metadata
├── Generate-AuthKey.ps1             # PowerShell key generation script
├── Process-Worker.ps1               # Worker template processing script
├── cloudflare-worker.template.js    # Worker template with injection points
├── cloudflare-worker.js             # Generated worker with authentication
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
- **Same URL**: `https://abuseipdb.workers.dev` for both (differentiated by environment variables)

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
- **Request Validation**: All requests are validated using HMAC-SHA256 authentication
- **Origin Control**: CORS headers restrict access to configured allowed origins
- **API Key Protection**: The AbuseIPDB API key is never exposed to client-side code

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all builds pass with the new authentication system
5. Submit a pull request
