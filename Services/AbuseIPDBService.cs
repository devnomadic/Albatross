using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System;
using System.Diagnostics;
using Microsoft.Extensions.Configuration;

namespace Albatross.Services
{
    /// <summary>
    /// Complete API response model for AbuseIPDB
    /// </summary>
    public class AbuseIPDBApiResponse
    {
        [JsonPropertyName("data")]
        public AbuseIPDBData? Data { get; set; }
    }

    /// <summary>
    /// Main data container for AbuseIPDB response
    /// </summary>
    public class AbuseIPDBData
    {
        [JsonPropertyName("ipAddress")]
        public string? IpAddress { get; set; }
        
        [JsonPropertyName("isPublic")]
        public bool IsPublic { get; set; }
        
        [JsonPropertyName("ipVersion")]
        public int IpVersion { get; set; }
        
        [JsonPropertyName("isWhitelisted")]
        public bool? IsWhitelisted { get; set; }
        
        [JsonPropertyName("abuseConfidenceScore")]
        public int AbuseConfidenceScore { get; set; }
        
        [JsonPropertyName("countryCode")]
        public string? CountryCode { get; set; }
        
        [JsonPropertyName("countryName")]
        public string? CountryName { get; set; }
        
        [JsonPropertyName("usageType")]
        public string? UsageType { get; set; }
        
        [JsonPropertyName("isp")]
        public string? ISP { get; set; }
        
        [JsonPropertyName("domain")]
        public string? Domain { get; set; }
        
        [JsonPropertyName("hostnames")]
        public List<string>? Hostnames { get; set; }
        
        [JsonPropertyName("totalReports")]
        public int TotalReports { get; set; }
        
        [JsonPropertyName("numDistinctUsers")]
        public int NumDistinctUsers { get; set; }
        
        [JsonPropertyName("lastReportedAt")]
        public string? LastReportedAt { get; set; }
        
        [JsonPropertyName("reports")]
        public List<AbuseReport>? Reports { get; set; }
    }
    
    /// <summary>
    /// Individual abuse report details
    /// </summary>
    public class AbuseReport
    {
        [JsonPropertyName("reportedAt")]
        public string? ReportedAt { get; set; }
        
        [JsonPropertyName("comment")]
        public string? Comment { get; set; }
        
        [JsonPropertyName("categories")]
        public List<int>? Categories { get; set; }
        
        [JsonPropertyName("reporterId")]
        public int ReporterId { get; set; }
        
        [JsonPropertyName("reporterCountryCode")]
        public string? ReporterCountryCode { get; set; }
        
        [JsonPropertyName("reporterCountryName")]
        public string? ReporterCountryName { get; set; }
    }

    /// <summary>
    /// Service for interacting with AbuseIPDB via Cloudflare Worker
    /// </summary>
    public class AbuseIPDBService
    {
        private readonly HttpClient _httpClient;
        private readonly string _cloudflareWorkerUrl;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly string _authKey;

        public AbuseIPDBService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            
            // Get settings from appsettings.json
            _cloudflareWorkerUrl = configuration["AbuseIPDB:WorkerUrl"] ?? "https://abuseipdb.devnomadic.workers.dev";
            _authKey = configuration["AbuseIPDB:ApiAccessToken"] ?? string.Empty;
            
            // Configure JSON options with proper property case handling
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
        }

        /// <summary>
        /// Checks an IP address against AbuseIPDB through a Cloudflare Worker
        /// </summary>
        /// <param name="ipAddress">The IP address to check</param>
        /// <param name="maxAgeInDays">Reports older than this many days won't be included (default 30)</param>
        /// <param name="verbose">Whether to include detailed report information</param>
        /// <returns>Complete AbuseIPDB information for the specified IP address</returns>
        public async Task<AbuseIPDBApiResponse> CheckIPAsync(string ipAddress, int maxAgeInDays = 30, bool verbose = true)
        {
            try
            {
                var requestUrl = $"{_cloudflareWorkerUrl}?ipAddress={ipAddress}&maxAgeInDays={maxAgeInDays}&verbose={verbose}";
                Console.WriteLine($"Requesting: {requestUrl}");
                
                // Create request message to add custom headers
                var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                
                // Add authentication using CF-Ray header if key is available
                if (!string.IsNullOrEmpty(_authKey))
                {
                    // Pass any existing CF-Ray header from the current session
                    var existingCfRay = _httpClient.DefaultRequestHeaders.GetValues("CF-Ray").FirstOrDefault();
                    if (!string.IsNullOrEmpty(existingCfRay))
                    {
                        request.Headers.Add("CF-Ray-Worker", _authKey);
                        Console.WriteLine("Added CF-Ray-Worker authentication header");
                    }
                }
                
                var response = await _httpClient.SendAsync(request);
                
                response.EnsureSuccessStatusCode();
                
                // Get the raw JSON string first for debugging
                var jsonString = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Response received: {jsonString}");
                
                if (string.IsNullOrWhiteSpace(jsonString))
                {
                    throw new Exception("Empty response received from AbuseIPDB service");
                }
                
                // Try to deserialize with System.Text.Json
                var result = JsonSerializer.Deserialize<AbuseIPDBApiResponse>(jsonString, _jsonOptions);
                
                if (result == null)
                {
                    throw new Exception("Failed to deserialize AbuseIPDB response");
                }
                
                return result;
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP request error: {ex.Message}");
                throw new Exception($"Error checking IP address: {ex.Message}", ex);
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"JSON parsing error: {ex.Message}");
                throw new Exception($"Error parsing AbuseIPDB response: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
                throw new Exception($"Unexpected error checking IP: {ex.Message}", ex);
            }
        }
    }
}