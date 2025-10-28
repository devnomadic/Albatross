# Albatross

A modern Blazor WebAssembly application that provides comprehensive IP address analysis and abuse checking functionality. Albatross combines cloud IP range detection with AbuseIPDB reputation checking and AI-powered risk assessment through a secure Cloudflare Worker proxy.

## Features

- **IP Abuse Checking**: Query the AbuseIPDB API to check if an IP address has been reported for malicious activity
- **AI-Powered Reputation Analysis**: Advanced risk assessment using Cloudflare Workers AI with Llama 3.1 70B Instruct model
- **Cloud IP Range Detection**: Identify if an IP address belongs to major cloud providers (AWS, Azure, GCP, Oracle Cloud)
- **Flexible Input Format**: Support for IP addresses with custom report age (e.g., `8.8.8.8;60` for 60 days of history)
- **Combined Data Sources**: Integrated AbuseIPDB, Cloudflare Radar API, and Workers AI for comprehensive IP analysis
- **Secure Authentication**: Build-time generated HMAC authentication with timestamp validation for enhanced security
- **CORS Protection**: Cloudflare Worker proxy handles CORS and protects API keys from client exposure
- **SEO-Optimized**: Static HTML prerendering for improved search engine indexing and web crawler accessibility
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

## Prerendering

Albatross uses **[BlazorWasmPreRendering.Build](https://github.com/jsakamoto/BlazorWasmPreRendering.Build)** to generate static HTML during the publish process, improving SEO and web crawler accessibility.

### How It Works
- **Build-Time Rendering**: During `dotnet publish`, the app is rendered to static HTML
- **SEO Benefits**: Search engines can index content without executing JavaScript
- **Hidden Content**: Prerendered HTML is hidden (opacity: 0, z-index: -1) to prevent visual flash
- **Blazor Hydration**: The app seamlessly takes over after loading, providing full interactivity
- **Zero Runtime Overhead**: Prerendering happens at build time, not on the server

### Implementation
For prerendering to work, service registration must be extracted into a static local function in `Program.cs`:
```csharp
static void ConfigureServices(IServiceCollection services, string baseAddress)
{
    services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(baseAddress) });
    services.AddScoped<AbuseIPDBService>(/* ... */);
}
```

See the [BlazorWasmPreRendering.Build documentation](https://github.com/jsakamoto/BlazorWasmPreRendering.Build#services-registration) for more details.

### Verification
To verify prerendering is working after deployment:
```bash
# Check for prerendering markers in the HTML
curl -s https://albatross.devnomadic.com | grep "PRERENDERING-BEGIN"

# Or view page source in browser and search for:
<!-- %%-PRERENDERING-BEGIN-%% -->
```

If prerendering is working, you'll see the full app structure in the HTML source, not just "Loading..."

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

## Testing

The project includes a comprehensive unit test suite to ensure IP range matching accuracy across IPv4 and IPv6 addresses.

### Test Coverage
- **Total Tests**: 41 unit tests
- **Test Framework**: xUnit 2.4.2
- **Target Framework**: .NET 8.0
- **Test Categories**:
  - IPv4 basic matching and validation
  - IPv6 basic matching and validation
  - Boundary condition testing (first/last address in ranges)
  - Edge cases (single hosts /32 and /128, large networks /0)
  - Real-world cloud provider IP ranges (AWS, Azure, GCP, Oracle)
  - Invalid input handling (malformed CIDR, out-of-range prefixes)
  - Mixed version validation (IPv4 vs IPv6 range mismatches)

### Running Tests

**Run all tests:**
```bash
dotnet test Tests/Albatross.Tests.csproj
```

**Run tests with detailed output:**
```bash
dotnet test Tests/Albatross.Tests.csproj --logger "console;verbosity=normal"
```

**Run tests as part of the build:**
```bash
./build.sh
```

The build script automatically:
1. Updates cloud IP manifests
2. Runs all unit tests
3. Builds and publishes the application (only if tests pass)

### Test Examples

**IPv4 Cloud Range Tests:**
- AWS EC2: `3.5.140.50` in `3.5.140.0/22` ✓
- AWS S3: `52.216.100.10` in `52.216.0.0/15` ✓
- Azure: `13.64.50.100` in `13.64.0.0/11` ✓
- GCP: `34.64.100.200` in `34.64.0.0/10` ✓
- Oracle: `132.145.100.50` in `132.145.0.0/16` ✓

**IPv6 Cloud Range Tests:**
- AWS CloudFront: `2600:9000:5300::1` in `2600:9000:5300::/40` ✓
- AWS EC2: `2600:1900:8000::1` in `2600:1900:8000::/44` ✓
- Azure: `2603:1030:100::1` in `2603:1030:100::/47` ✓
- GCP: `2001:4860:4860::8888` in `2001:4860:4860::/48` ✓

**Boundary & Edge Cases:**
- First/last addresses in ranges
- Single host ranges (/32 for IPv4, /128 for IPv6)
- Large networks (/0 ranges)
- Invalid CIDR notation handling

### CI/CD Integration

Tests are automatically run as part of the CI/CD pipeline:
- **Pre-deployment validation**: Tests must pass before any deployment
- **Build verification**: Each build runs the full test suite
- **Continuous integration**: Tests run on all pull requests and commits

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
The project includes comprehensive GitHub Actions workflows in `.github/workflows/`:

**🚀 Deployment Workflows:**
- **`deploy-dev.yml`**: Handles development and preview deployments
- **`deploy-production.yml`**: Handles production deployments

**🔧 CI/CD Workflows:**
- **`ci.yml`**: Runs tests, code formatting checks, and builds

**🛡️ Security Workflows:**
- **`codeql.yml`**: GitHub's CodeQL security analysis for code vulnerabilities
- **`dependency-review.yml`**: Reviews dependencies for security vulnerabilities in PRs

These workflows automatically:
- Generate authentication keys during CI/CD
- Build and deploy the Blazor WebAssembly app to Cloudflare Pages
- Process and deploy the Cloudflare Worker to static preview or production workers
- Create preview environments for feature branches and PRs
- Maintain a shared `abuseipdb-preview` worker for all development deployments
- Perform comprehensive security scanning on code and dependencies
- Analyze C# and JavaScript/TypeScript code for vulnerabilities

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
├── Tests/                           # Unit test suite
│   ├── Albatross.Tests.csproj       # Test project configuration
│   └── IpRangeTests.cs              # 41 IPv4/IPv6 range matching tests
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
- **Cloudflare Workers AI**: AI-powered risk assessment using Llama 3.1 70B Instruct model
- **Parallel Processing**: All APIs are queried simultaneously for optimal performance
- **Graceful Degradation**: Partial results if one API fails

### AI-Powered Reputation Analysis
The worker uses Cloudflare Workers AI with the Llama 3.1 70B Instruct model to generate intelligent risk assessments:
- **Real-time Analysis**: Analyzes data from AbuseIPDB and Cloudflare Radar APIs
- **Risk Levels**: Categorizes threats as low, medium, high, or critical
- **Trust Scores**: Provides 0-100 trust score for quick assessment
- **AI Summary**: Natural language explanation of the IP's reputation
- **Actionable Recommendations**: Specific steps to take based on the analysis
- **Model**: `@cf/meta/llama-3.1-70b-instruct` (70 billion parameter model)

Example AI Response:
```json
{
  "aiReputation": {
    "success": true,
    "analysis": {
      "riskLevel": "medium",
      "trustScore": 65,
      "summary": "This IP from US shows moderate abuse activity with 15 reports. ISP indicates datacenter usage which is common for both legitimate and malicious traffic.",
      "recommendations": [
        "Review the specific abuse reports for patterns",
        "Consider rate limiting if used for API access"
      ]
    },
    "model": "@cf/meta/llama-3.1-70b-instruct",
    "timestamp": "2025-10-28T04:45:00.000Z"
  }
}
```

## Current Status

✅ **Authentication System**: Fully implemented and working
✅ **CORS Security**: Browser-only validation enabled  
✅ **Production Deployment**: Live at `https://albatross.devnomadic.com`
✅ **Build System**: Automated key generation and injection working
✅ **GitHub Actions**: Automated CI/CD pipeline functional
✅ **Security Scanning**: CodeQL and dependency review workflows active
✅ **Code Quality**: Automated formatting and testing in CI/CD
✅ **AI Integration**: Cloudflare Workers AI with Llama 3.1 70B for reputation analysis

## Image Credits

This project uses free images sourced from:

- **[Flaticon](https://www.flaticon.com/)** - Free icons and graphics
- **[Unsplash](https://unsplash.com/)** - Free high-quality photography

We appreciate these platforms for providing free resources to the developer community.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all builds pass with the new authentication system
5. Submit a pull request
