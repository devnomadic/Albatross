#!/bin/sh

echo "🚀 Starting Albatross build process..."

# Update cloud IP manifests first
echo "🌐 Updating cloud IP manifests..."
if [ -f "./update-manifests.sh" ]; then
    ./update-manifests.sh
else
    echo "⚠️  Manifest update script not found, skipping manifest update"
fi

echo "🔧 Installing .NET 8.0..."
curl -sSL https://dot.net/v1/dotnet-install.sh > dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh -c 8.0 -InstallDir ./dotnet

echo "🏗️ Building and publishing application..."
./dotnet/dotnet --version
./dotnet/dotnet publish Albatross.csproj -c Release -o output

echo "🎉 Build completed successfully!"