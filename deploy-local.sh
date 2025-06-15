#!/bin/bash

# Local deployment helper script for Albatross
# This script helps test the deployment process locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOTNET_VERSION="8.0"
NODE_VERSION="18"

echo -e "${BLUE}🚀 Albatross Local Deployment Helper${NC}"
echo "=============================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
echo -e "${BLUE}📋 Checking prerequisites...${NC}"

if command_exists dotnet; then
    DOTNET_VER=$(dotnet --version | cut -d. -f1,2)
    if [[ "$DOTNET_VER" == "8.0" ]]; then
        print_status ".NET $DOTNET_VER is installed"
    else
        print_warning ".NET version is $DOTNET_VER, but 8.0 is recommended"
    fi
else
    print_error ".NET is not installed. Please install .NET 8.0 SDK"
    exit 1
fi

if command_exists node; then
    NODE_VER=$(node --version | cut -c2- | cut -d. -f1)
    if [[ "$NODE_VER" -ge "18" ]]; then
        print_status "Node.js $NODE_VER is installed"
    else
        print_warning "Node.js version is $NODE_VER, but 18+ is recommended"
    fi
else
    print_warning "Node.js is not installed. Install it for worker deployment"
fi

if command_exists wrangler; then
    print_status "Wrangler CLI is installed"
else
    print_warning "Wrangler CLI is not installed. Install with: npm install -g wrangler"
fi

echo ""

# Menu
while true; do
    echo -e "${BLUE}📋 Select an action:${NC}"
    echo "1. Build and test SPA locally"
    echo "2. Deploy worker to staging"
    echo "3. Deploy worker to production"
    echo "4. Test worker locally"
    echo "5. Update IP manifests"
    echo "6. Run security scan"
    echo "7. Validate all configurations"
    echo "8. Setup GitHub secrets template"
    echo "9. Exit"
    echo ""
    read -p "Enter your choice (1-9): " choice

    case $choice in
        1)
            echo -e "${BLUE}🏗️  Building SPA locally...${NC}"
            
            # Update manifests
            if [ -f "./update-manifests.sh" ]; then
                print_status "Updating IP manifests..."
                chmod +x ./update-manifests.sh
                ./update-manifests.sh
            fi
            
            # Restore and build
            print_status "Restoring dependencies..."
            dotnet restore
            
            print_status "Building application..."
            dotnet build --configuration Release
            
            print_status "Publishing application..."
            dotnet publish Albatross.csproj --configuration Release --output ./local-dist
            
            print_status "SPA built successfully!"
            echo -e "${GREEN}📁 Output directory: ./local-dist/wwwroot/${NC}"
            ;;
            
        2)
            echo -e "${BLUE}🚀 Deploying worker to staging...${NC}"
            if command_exists wrangler; then
                npm run deploy:staging 2>/dev/null || wrangler deploy --env staging
                print_status "Worker deployed to staging!"
            else
                print_error "Wrangler CLI not found. Install with: npm install -g wrangler"
            fi
            ;;
            
        3)
            echo -e "${BLUE}🚀 Deploying worker to production...${NC}"
            if command_exists wrangler; then
                npm run deploy:production 2>/dev/null || wrangler deploy --env production
                print_status "Worker deployed to production!"
            else
                print_error "Wrangler CLI not found. Install with: npm install -g wrangler"
            fi
            ;;
            
        4)
            echo -e "${BLUE}🧪 Testing worker locally...${NC}"
            if command_exists wrangler; then
                print_status "Starting local worker development server..."
                echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
                wrangler dev cloudflare-worker.js
            else
                print_error "Wrangler CLI not found. Install with: npm install -g wrangler"
            fi
            ;;
            
        5)
            echo -e "${BLUE}🌐 Updating IP manifests...${NC}"
            if [ -f "./update-manifests.sh" ]; then
                chmod +x ./update-manifests.sh
                ./update-manifests.sh
                print_status "IP manifests updated!"
            else
                print_error "update-manifests.sh not found"
            fi
            ;;
            
        6)
            echo -e "${BLUE}🛡️  Running security scan...${NC}"
            dotnet restore
            print_status "Checking for vulnerable packages..."
            dotnet list package --vulnerable --include-transitive
            print_status "Security scan completed!"
            ;;
            
        7)
            echo -e "${BLUE}✅ Validating configurations...${NC}"
            
            # Check .NET project
            if [ -f "Albatross.csproj" ]; then
                print_status "Found Albatross.csproj"
            else
                print_error "Albatross.csproj not found"
            fi
            
            # Check worker
            if [ -f "cloudflare-worker.js" ]; then
                print_status "Found cloudflare-worker.js"
                if command_exists node; then
                    node -c cloudflare-worker.js && print_status "Worker syntax is valid"
                fi
            else
                print_error "cloudflare-worker.js not found"
            fi
            
            # Check wrangler config
            if [ -f "wrangler.toml" ]; then
                print_status "Found wrangler.toml"
            else
                print_warning "wrangler.toml not found"
            fi
            
            # Check package.json
            if [ -f "package.json" ]; then
                print_status "Found package.json"
            else
                print_warning "package.json not found"
            fi
            
            # Check GitHub workflows
            if [ -d ".github/workflows" ]; then
                WORKFLOW_COUNT=$(ls .github/workflows/*.yml 2>/dev/null | wc -l)
                print_status "Found $WORKFLOW_COUNT GitHub workflow(s)"
            else
                print_warning "No GitHub workflows found"
            fi
            ;;
            
        8)
            echo -e "${BLUE}📝 GitHub Secrets Template${NC}"
            echo ""
            echo "Add these secrets to your GitHub repository:"
            echo "(Settings > Secrets and variables > Actions)"
            echo ""
            echo -e "${YELLOW}Required for Cloudflare deployment:${NC}"
            echo "CLOUDFLARE_API_TOKEN=your_cloudflare_api_token"
            echo "CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id"
            echo ""
            echo -e "${YELLOW}Optional (for Cloudflare Pages):${NC}"
            echo "CLOUDFLARE_PROJECT_NAME=your_project_name"
            echo ""
            echo -e "${YELLOW}Optional (for enhanced security):${NC}"
            echo "ABUSEIPDB_API_KEY=your_abuseipdb_key"
            echo "WORKER_AUTH_KEY=your_worker_auth_key"
            echo ""
            echo -e "${GREEN}💡 Tip: Visit DEPLOYMENT.md for detailed setup instructions${NC}"
            ;;
            
        9)
            echo -e "${GREEN}👋 Goodbye!${NC}"
            exit 0
            ;;
            
        *)
            print_error "Invalid choice. Please enter a number between 1-9."
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
    echo ""
done
