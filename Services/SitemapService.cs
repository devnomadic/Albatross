using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using System.Text;
using System.Xml;
using System.IO;
using System.Reflection;

namespace Albatross.Services
{
    /// <summary>
    /// Service for generating dynamic sitemaps for the Albatross application
    /// </summary>
    public class SitemapService
    {
        private readonly string _baseUrl;
        private readonly string _contentRoot;

        public SitemapService(string baseUrl = "https://albatross.devnomadic.com", string? contentRoot = null)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _contentRoot = contentRoot ?? GetContentRoot();
        }

        /// <summary>
        /// Generates a complete sitemap XML string
        /// </summary>
        public string GenerateSitemap()
        {
            var sitemap = new StringBuilder();
            sitemap.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sitemap.AppendLine("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"");
            sitemap.AppendLine("        xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"");
            sitemap.AppendLine("        xsi:schemaLocation=\"http://www.sitemaps.org/schemas/sitemap/0.9");
            sitemap.AppendLine("        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd\">");
            sitemap.AppendLine();

            // Main page
            AddUrl(sitemap, "/", DateTime.UtcNow, "weekly", "1.0");

            // IP Manifests (dynamically discovered from filesystem)
            var manifestFiles = GetIpManifestFiles();
            foreach (var manifest in manifestFiles)
            {
                var lastModified = GetFileLastModified(manifest);
                AddUrl(sitemap, $"/ip-manifests/{Path.GetFileName(manifest)}", lastModified, "daily", "0.8");
            }

            // Static files
            AddUrl(sitemap, "/robots.txt", DateTime.UtcNow, "monthly", "0.3");

            sitemap.AppendLine("  <!-- Note: Search functionality intentionally excluded per robots.txt -->");
            sitemap.AppendLine("  <!-- AbuseIPDB search endpoints are blocked from crawling -->");
            sitemap.AppendLine();
            sitemap.AppendLine("</urlset>");

            return sitemap.ToString();
        }

        /// <summary>
        /// Writes the sitemap to a file
        /// </summary>
        public async Task<bool> WriteSitemapToFileAsync(string outputPath)
        {
            try
            {
                var sitemapContent = GenerateSitemap();
                await File.WriteAllTextAsync(outputPath, sitemapContent, Encoding.UTF8);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error writing sitemap: {ex.Message}");
                return false;
            }
        }



        private void AddUrl(StringBuilder sitemap, string path, DateTime lastMod, string changeFreq, string priority)
        {
            sitemap.AppendLine("  <url>");
            sitemap.AppendLine($"    <loc>{_baseUrl}{path}</loc>");
            sitemap.AppendLine($"    <lastmod>{lastMod:yyyy-MM-dd}</lastmod>");
            sitemap.AppendLine($"    <changefreq>{changeFreq}</changefreq>");
            sitemap.AppendLine($"    <priority>{priority}</priority>");
            sitemap.AppendLine("  </url>");
            sitemap.AppendLine();
        }

        private string[] GetIpManifestFiles()
        {
            var manifestDir = Path.Combine(_contentRoot, "wwwroot", "ip-manifests");
            if (!Directory.Exists(manifestDir))
            {
                return Array.Empty<string>();
            }

            return Directory.GetFiles(manifestDir, "*.json")
                           .OrderBy(f => Path.GetFileName(f))
                           .ToArray();
        }

        private DateTime GetFileLastModified(string filePath)
        {
            try
            {
                return File.GetLastWriteTimeUtc(filePath);
            }
            catch
            {
                return DateTime.UtcNow;
            }
        }

        private static string GetContentRoot()
        {
            // Try to get the content root from the executing assembly location
            var assemblyLocation = Assembly.GetExecutingAssembly().Location;
            if (!string.IsNullOrEmpty(assemblyLocation))
            {
                var dir = new DirectoryInfo(Path.GetDirectoryName(assemblyLocation)!);

                // Walk up the directory tree to find the project root
                while (dir != null && dir.Exists)
                {
                    if (dir.GetFiles("*.csproj").Any() || dir.GetDirectories("wwwroot").Any())
                    {
                        return dir.FullName;
                    }
                    dir = dir.Parent;
                }
            }

            // Fallback to current directory
            return Directory.GetCurrentDirectory();
        }
    }
}
