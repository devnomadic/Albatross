#!/bin/sh

echo "🚀 Starting Albatross build process..."

# Update cloud IP manifests first
echo "🌐 Updating cloud IP manifests..."
if [ -f "./update-manifests.sh" ]; then
    ./update-manifests.sh
else
    echo "⚠️  Manifest update script not found, skipping manifest update"
fi

# Determine which dotnet to use
if command -v dotnet >/dev/null 2>&1; then
    echo "✅ Using globally installed .NET SDK"
    DOTNET_CMD="dotnet"
else
    echo "🔧 Installing .NET 8.0 locally..."
    curl -sSL https://dot.net/v1/dotnet-install.sh > dotnet-install.sh
    chmod +x dotnet-install.sh
    ./dotnet-install.sh -c 8.0 -InstallDir ./dotnet
    DOTNET_CMD="./dotnet/dotnet"
fi

echo "🧪 Running unit tests..."
$DOTNET_CMD test Tests/Albatross.Tests.csproj --logger "console;verbosity=normal"
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -ne 0 ]; then
    echo "❌ Tests failed! Build aborted."
    exit $TEST_EXIT_CODE
fi

echo "✅ All tests passed!"

echo "🏗️ Building and publishing application..."
$DOTNET_CMD --version
$DOTNET_CMD publish Albatross.csproj -c Release -o output

echo "🎉 Build completed successfully!"