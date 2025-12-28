#!/bin/sh

echo "🌐 Updating cloud IP manifests..."

# Create the ip-manifests directory if it doesn't exist
mkdir -p ./wwwroot/ip-manifests

# Backup existing manifests
echo "📦 Creating backup of existing manifests..."
mkdir -p ./manifest-backup
cp ./wwwroot/ip-manifests/*.json ./manifest-backup/ 2>/dev/null || true

# Fetch AWS IP ranges
echo "📡 Downloading AWS IP ranges..."
curl -sSL "https://ip-ranges.amazonaws.com/ip-ranges.json" -o ./wwwroot/ip-manifests/aws.json
if [ $? -eq 0 ]; then
    echo "✅ AWS manifest updated successfully"
    # Show some basic info about the file
    echo "   Size: $(wc -c < ./wwwroot/ip-manifests/aws.json) bytes"
    echo "   Sync Token: $(grep -o '"syncToken":"[^"]*"' ./wwwroot/ip-manifests/aws.json | cut -d'"' -f4)"
else
    echo "❌ Failed to download AWS manifest"
fi

# Fetch GCP IP ranges
echo "📡 Downloading GCP IP ranges..."
curl -sSL "https://www.gstatic.com/ipranges/cloud.json" -o ./wwwroot/ip-manifests/gcp.json
if [ $? -eq 0 ]; then
    echo "✅ GCP manifest updated successfully"
    # Show some basic info about the file
    echo "   Size: $(wc -c < ./wwwroot/ip-manifests/gcp.json) bytes"
    echo "   Creation Time: $(grep -o '"creationTime":"[^"]*"' ./wwwroot/ip-manifests/gcp.json | cut -d'"' -f4)"
else
    echo "❌ Failed to download GCP manifest"
fi

# Fetch Oracle IP ranges
echo "📡 Downloading Oracle IP ranges..."
curl -sSL "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json" -o ./wwwroot/ip-manifests/oracle.json
if [ $? -eq 0 ]; then
    echo "✅ Oracle manifest updated successfully"
    # Show some basic info about the file
    echo "   Size: $(wc -c < ./wwwroot/ip-manifests/oracle.json) bytes"
    echo "   Last Updated: $(grep -o '"last_updated_timestamp":"[^"]*"' ./wwwroot/ip-manifests/oracle.json | cut -d'"' -f4)"
else
    echo "❌ Failed to download Oracle manifest"
fi

# Fetch Azure IP ranges
echo "📡 Downloading Azure IP ranges..."
# Use the Azure REST API to get the latest Service Tags
# This API provides a reliable way to get the current service tags
curl -sSL "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519" > /tmp/azure_page.html 2>/dev/null
AZURE_URL=$(grep -o 'https://download.microsoft.com/download/[^"]*ServiceTags[^"]*\.json' /tmp/azure_page.html | head -1)

if [ -n "$AZURE_URL" ]; then
    curl -sSL "$AZURE_URL" -o ./wwwroot/ip-manifests/azure.json
    if [ $? -eq 0 ] && [ -s ./wwwroot/ip-manifests/azure.json ]; then
        # Verify it's actually JSON and not an error page
        if grep -q '"changeNumber"' ./wwwroot/ip-manifests/azure.json; then
            echo "✅ Azure manifest updated successfully"
            echo "   Size: $(wc -c < ./wwwroot/ip-manifests/azure.json) bytes"
            echo "   Change Number: $(grep -o '"changeNumber":[^,]*' ./wwwroot/ip-manifests/azure.json | head -1 | cut -d':' -f2)"
            SUCCESS=true
        else
            echo "❌ Downloaded Azure file is not valid JSON"
            SUCCESS=false
        fi
    else
        echo "❌ Failed to download Azure manifest from discovered URL"
        SUCCESS=false
    fi
else
    echo "❌ Could not discover current Azure Service Tags URL"
    SUCCESS=false
fi

# If the API method failed, try direct URLs with recent dates as fallback
if [ "$SUCCESS" != true ]; then
    echo "🔄 Trying fallback method with recent dates..."
    for i in 0 1 2 3 4 5 6 7 14 21; do
        if [ "$(uname)" = "Darwin" ]; then
            # macOS date command
            DATE=$(date -j -v-${i}d +%Y%m%d 2>/dev/null)
        else
            # Linux date command
            DATE=$(date -d "${i} days ago" +%Y%m%d 2>/dev/null)
        fi
        
        if [ -n "$DATE" ]; then
            URL="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_${DATE}.json"
            curl -sSL "$URL" -o ./wwwroot/ip-manifests/Azure.json 2>/dev/null
            if [ $? -eq 0 ] && [ -s ./wwwroot/ip-manifests/Azure.json ]; then
                # Verify it's actually JSON and not an error page
                if grep -q '"changeNumber"' ./wwwroot/ip-manifests/Azure.json; then
                    echo "✅ Azure manifest updated successfully (using ${DATE})"
                    echo "   Size: $(wc -c < ./wwwroot/ip-manifests/Azure.json) bytes"
                    echo "   Change Number: $(grep -o '"changeNumber":[^,]*' ./wwwroot/ip-manifests/Azure.json | head -1 | cut -d':' -f2)"
                    SUCCESS=true
                    break
                fi
            fi
        fi
    done
fi

if [ "$SUCCESS" != true ]; then
    echo "❌ Failed to download Azure manifest - keeping existing version"
    # Restore from backup if download failed
    cp ./manifest-backup/Azure.json ./wwwroot/ip-manifests/ 2>/dev/null || true
fi

# Clean up temp file
rm -f /tmp/azure_page.html

echo "🎉 Manifest update completed!"
