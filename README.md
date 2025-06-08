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
- PowerShell (cross-platform)
- AbuseIPDB API key
- Cloudflare Workers account (for deployment)

### Local Development
1. Clone the repository
2. Update `cloudflare-worker.template.js` with your AbuseIPDB API key
3. Build the project: `dotnet build`
4. Run the application: `dotnet run`

### Deployment
1. **Build**: Run `dotnet build` to generate authentication keys
2. **Deploy Worker**: Upload `cloudflare-worker.js` to your Cloudflare Workers account
3. **Update Endpoint**: Configure the worker URL in `AbuseIPDBService.cs`
4. **Deploy App**: Use your preferred hosting platform (GitHub Pages, Azure Static Web Apps, etc.)

### GitHub Actions
The project includes automated deployment workflows in `.github/workflows/` that:
- Automatically generate authentication keys during CI/CD
- Build and deploy the Blazor WebAssembly app
- Handle the Cloudflare Worker deployment

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

### GitHub Secrets
For automated deployment, configure these secrets in your repository settings:

**Required for Cloudflare Deployment:**
- `CLOUDFLARE_API_TOKEN` - Your Cloudflare API token
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID  
- `CLOUDFLARE_PAGES_PROJECT` - Your Cloudflare Pages project name

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
