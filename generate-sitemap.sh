#!/bin/bash

# Simple sitemap generation script
# Usage: ./generate-sitemap.sh

DOMAIN="https://albatross.devnomadic.com"
CURRENT_DATE=$(date -u +"%Y-%m-%d")
OUTPUT_FILE="wwwroot/sitemap.xml"

echo "Generating sitemap for $DOMAIN..."

# Create sitemap XML
cat > "$OUTPUT_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">

  <!-- Main Application Page -->
  <url>
    <loc>$DOMAIN/</loc>
    <lastmod>$CURRENT_DATE</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
EOF

# Add IP manifest files
if [ -d "wwwroot/ip-manifests" ]; then
    for file in wwwroot/ip-manifests/*.json; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            cat >> "$OUTPUT_FILE" << EOF
  <url>
    <loc>$DOMAIN/ip-manifests/$filename</loc>
    <lastmod>$CURRENT_DATE</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
EOF
        fi
    done
fi

# Add robots.txt and closing
cat >> "$OUTPUT_FILE" << EOF
  <url>
    <loc>$DOMAIN/robots.txt</loc>
    <lastmod>$CURRENT_DATE</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.3</priority>
  </url>

  <!-- Note: Search functionality intentionally excluded per robots.txt -->
  <!-- AbuseIPDB search endpoints are blocked from crawling -->

</urlset>
EOF

echo "Sitemap generated: $OUTPUT_FILE"
