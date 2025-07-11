# GitHub Actions Deployment Guide

This repository includes automated deployment pipelines for both the Blazor WebAssembly SPA and Cloudflare Worker.

## 🚀 Automatic Deployment

The GitHub Actions pipeline automatically:
- ✅ Builds the Blazor WebAssembly application
- ✅ Updates cloud IP manifests 
- ✅ Deploys to GitHub Pages or Cloudflare Pages
- ✅ Deploys the Cloudflare Worker
- ✅ Runs security scans

## 🔧 Required GitHub Secrets

Configure the following secrets in your GitHub repository settings (`Settings > Secrets and variables > Actions`):

### Cloudflare Configuration
- `CLOUDFLARE_API_TOKEN` - Your Cloudflare API token with Worker and Pages permissions
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID
- `CLOUDFLARE_PROJECT_NAME` - Your Cloudflare Pages project name (if using Cloudflare Pages)

### Worker Secrets (Optional - for enhanced security)
- `ABUSEIPDB_API_KEY` - Your AbuseIPDB API key (if not hardcoded in worker)
- `WORKER_AUTH_KEY` - Authentication key for HMAC validation (if not hardcoded in worker)

## 📋 Setup Instructions

### 1. Cloudflare Setup

1. **Get your Cloudflare Account ID:**
   ```bash
   # Visit Cloudflare Dashboard > Right sidebar shows Account ID
   ```

2. **Create a Cloudflare API Token:**
   - Go to Cloudflare Dashboard > My Profile > API Tokens
   - Click "Create Token"
   - Use "Custom token" template
   - Permissions needed:
     - `Account:Cloudflare Workers:Edit`
     - `Zone:Zone Settings:Read` (if using custom domains)
     - `Zone:Page Rules:Edit` (if using custom domains)

3. **Create Cloudflare Pages Project (Optional):**
   ```bash
   # Alternative to GitHub Pages for hosting the SPA
   # Can be done through Cloudflare Dashboard > Pages
   ```

### 2. GitHub Repository Setup

1. **Add secrets to your repository:**
   - Go to `Settings > Secrets and variables > Actions`
   - Add the secrets listed above

2. **Enable GitHub Pages (if using GitHub Pages):**
   - Go to `Settings > Pages`
   - Source: "Deploy from a branch"
   - Branch: `gh-pages`

### 3. Local Development Setup

1. **Install Wrangler CLI:**
   ```bash
   npm install -g wrangler
   ```

2. **Authenticate with Cloudflare:**
   ```bash
   wrangler auth login
   ```

3. **Test worker locally:**
   ```bash
   wrangler dev cloudflare-worker.js
   ```

4. **Deploy worker manually:**
   ```bash
   wrangler deploy
   ```

## 🔄 Deployment Triggers

- **Automatic:** Push to `main` or `master` branch
- **Manual:** Use "Run workflow" button in GitHub Actions tab
- **Pull Request:** Builds and tests (but doesn't deploy)

## 📁 Build Artifacts

- SPA build artifacts are uploaded to GitHub Actions
- Retention period: 30 days
- Can be downloaded for manual deployment if needed

## 🛡️ Security Features

- Automated security vulnerability scanning
- CodeQL analysis for C# and JavaScript
- HMAC-based authentication between SPA and Worker
- Secrets management through GitHub Actions

## 🌐 Deployment Options

### Option 1: GitHub Pages + Cloudflare Worker
- SPA hosted on GitHub Pages
- Worker deployed to Cloudflare Workers
- Free tier friendly

### Option 2: Cloudflare Pages + Cloudflare Worker  
- Both SPA and Worker on Cloudflare
- Better integration and performance
- Custom domains easier to configure

## 📊 Monitoring

After deployment, monitor your services:

1. **Cloudflare Worker:**
   ```bash
   wrangler tail albatross-worker
   ```

2. **GitHub Pages:**
   - Check Actions tab for deployment status
   - Visit your GitHub Pages URL

3. **Cloudflare Pages:**
   - Check Cloudflare Dashboard > Pages
   - View deployment logs and analytics

## 🔧 Troubleshooting

### Common Issues:

1. **Worker deployment fails:**
   - Check API token permissions
   - Verify account ID is correct
   - Ensure wrangler.toml is valid

2. **SPA deployment fails:**
   - Check .NET 8.0 compatibility
   - Verify build output path
   - Check GitHub Pages settings

3. **HMAC authentication errors:**
   - Ensure AUTH_KEY matches between SPA and Worker
   - Check URL case sensitivity handling
   - Verify HMAC token generation

### Debug Commands:

```bash
# Check worker logs
wrangler tail

# Test worker locally
wrangler dev

# Validate wrangler.toml
wrangler whoami

# Check GitHub Actions logs
# Go to Actions tab in GitHub repository
```

## 📚 Additional Resources

- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Blazor WebAssembly Deployment](https://docs.microsoft.com/en-us/aspnet/core/blazor/host-and-deploy/webassembly)
