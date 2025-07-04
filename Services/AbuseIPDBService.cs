using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Albatross.Generated;

namespace Albatross.Services
{
    /// <summary>
    /// Complete API response model for AbuseIPDB with integrated ASN information
    /// </summary>
    public class AbuseIPDBApiResponse
    {
        [JsonPropertyName("data")]
        public AbuseIPDBData? Data { get; set; }

        [JsonPropertyName("asnInfo")]
        public AsnInfo? AsnInfo { get; set; }

        [JsonPropertyName("abuseIPDBError")]
        public string? AbuseIPDBError { get; set; }

        [JsonPropertyName("workerInfo")]
        public WorkerInfo? WorkerInfo { get; set; }
    }

    /// <summary>
    /// ASN information from Cloudflare Radar API
    /// </summary>
    public class AsnInfo
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("data")]
        public AsnData? Data { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }

    /// <summary>
    /// ASN data details
    /// </summary>
    public class AsnData
    {
        [JsonPropertyName("asn")]
        public AsnDetails? Asn { get; set; }
    }

    /// <summary>
    /// Detailed ASN information
    /// </summary>
    public class AsnDetails
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("nameLong")]
        public string? NameLong { get; set; }

        [JsonPropertyName("aka")]
        public string? Aka { get; set; }

        [JsonPropertyName("asn")]
        public int AsnNumber { get; set; }

        [JsonPropertyName("website")]
        public string? Website { get; set; }

        [JsonPropertyName("country")]
        public string? Country { get; set; }

        [JsonPropertyName("countryName")]
        public string? CountryName { get; set; }

        [JsonPropertyName("orgName")]
        public string? OrgName { get; set; }

        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("related")]
        public List<RelatedAsn>? Related { get; set; }

        [JsonPropertyName("confidenceLevel")]
        public int ConfidenceLevel { get; set; }

        [JsonPropertyName("estimatedUsers")]
        public EstimatedUsers? EstimatedUsers { get; set; }
    }

    /// <summary>
    /// Related ASN information
    /// </summary>
    public class RelatedAsn
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("aka")]
        public string? Aka { get; set; }

        [JsonPropertyName("asn")]
        public int Asn { get; set; }

        [JsonPropertyName("estimatedUsers")]
        public int? EstimatedUsers { get; set; }
    }

    /// <summary>
    /// Estimated users information
    /// </summary>
    public class EstimatedUsers
    {
        [JsonPropertyName("estimatedUsers")]
        public int? TotalEstimatedUsers { get; set; }

        [JsonPropertyName("locations")]
        public List<LocationUsers>? Locations { get; set; }
    }

    /// <summary>
    /// Users by location
    /// </summary>
    public class LocationUsers
    {
        [JsonPropertyName("estimatedUsers")]
        public int? EstimatedUsers { get; set; }

        [JsonPropertyName("locationName")]
        public string? LocationName { get; set; }

        [JsonPropertyName("locationAlpha2")]
        public string? LocationAlpha2 { get; set; }
    }

    /// <summary>
    /// Worker metadata information
    /// </summary>
    public class WorkerInfo
    {
        [JsonPropertyName("buildInfo")]
        public BuildInfo? BuildInfo { get; set; }

        [JsonPropertyName("timestamp")]
        public string? Timestamp { get; set; }

        [JsonPropertyName("requestId")]
        public string? RequestId { get; set; }

        [JsonPropertyName("sources")]
        public Dictionary<string, string>? Sources { get; set; }
    }

    /// <summary>
    /// Build information from worker
    /// </summary>
    public class BuildInfo
    {
        [JsonPropertyName("buildId")]
        public string? BuildId { get; set; }

        [JsonPropertyName("buildTimestamp")]
        public string? BuildTimestamp { get; set; }

        [JsonPropertyName("keySource")]
        public string? KeySource { get; set; }
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

        public AbuseIPDBService(HttpClient httpClient)
        {
            _httpClient = httpClient;

            // Determine worker URL based on environment
            _cloudflareWorkerUrl = GetWorkerUrl();
            Debug.WriteLine($"AbuseIPDB Worker URL: {_cloudflareWorkerUrl}");

            // Try to use generated key first, fallback to hardcoded for development
            try
            {
                _authKey = BuildConstants.AuthKey;
                Debug.WriteLine($"Using generated auth key (Build ID: {BuildConstants.BuildId})");
            }
            catch (Exception)
            {
                throw new InvalidOperationException("BuildConstants.AuthKey is not available. Ensure the project is built with proper configuration.");
            }

            // Configure JSON options with proper property case handling
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };
        }

        /// <summary>
        /// Determines the appropriate worker URL based on the build configuration
        /// </summary>
        private static string GetWorkerUrl()
        {
            // Try to use build-time generated worker URL first
            try
            {
                var workerUrl = BuildConstants.WorkerUrl;
                Debug.WriteLine($"Using build-time worker URL: {workerUrl} (Environment: {BuildConstants.Environment})");
                return workerUrl.ToLower();
            }
            catch (Exception)
            {
                // Fallback if BuildConstants are not available - default to production
                Debug.WriteLine("BuildConstants not available, using production worker as fallback");
                return "https://abuseipdb.devnomadic.workers.dev/";
            }
        }

        /// <summary>
        /// Decodes a Base64 encoded string
        /// </summary>
        private static string? DecodeBase64(string? encodedValue)
        {
            if (string.IsNullOrEmpty(encodedValue))
                return encodedValue;

            try
            {
                var bytes = Convert.FromBase64String(encodedValue);
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                // If decoding fails, return the original value (for backward compatibility)
                return encodedValue;
            }
        }

        /// <summary>
        /// Generates an HMAC-SHA256 token using the auth key and full request URL (including timestamp parameter)
        /// </summary>
        /// <param name="requestUrl">The full request URL including query parameters and timestamp</param>
        /// <returns>Base64-encoded HMAC hash</returns>
        private string GenerateHmacToken(string requestUrl)
        {
            if (string.IsNullOrEmpty(_authKey) || string.IsNullOrEmpty(requestUrl))
            {
                return string.Empty;
            }

            try
            {
                // Use the full request URL (which includes timestamp parameter) as the message
                var message = requestUrl;

                // Convert message and key to byte arrays
                var messageBytes = Encoding.UTF8.GetBytes(message);
                var keyBytes = Encoding.UTF8.GetBytes(_authKey);

                // Debug logging
                Debug.WriteLine($"HMAC Generation - Message: {message}");
                Debug.WriteLine($"HMAC Generation - Auth Key Length: {_authKey.Length}");
                Debug.WriteLine($"HMAC Generation - Auth Key Preview: {_authKey.Substring(0, Math.Min(8, _authKey.Length))}...");

                // Create and compute the HMAC
                using (var hmac = new HMACSHA256(keyBytes))
                {
                    var hashBytes = hmac.ComputeHash(messageBytes);
                    // Convert hash to Base64 string
                    var token = Convert.ToBase64String(hashBytes);
                    Debug.WriteLine($"HMAC Generation - Token Preview: {token.Substring(0, Math.Min(20, token.Length))}...");
                    return token;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error generating HMAC token: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the current UTC timestamp in YYYYMMDDHHMM format
        /// </summary>
        /// <returns>Timestamp string</returns>
        private string GetTimestamp()
        {
            return DateTime.UtcNow.ToString("yyyyMMddHHmm");
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
                var verboseParam = verbose.ToString().ToLower();
                var timestamp = GetTimestamp();
                
                // Include timestamp as a URI parameter
                var requestUrl = $"{_cloudflareWorkerUrl}?ipAddress={ipAddress}&maxAgeInDays={maxAgeInDays}&verbose={verboseParam}&timestamp={timestamp}".ToLower();
                Console.WriteLine($"Requesting: {requestUrl}");

                // Create request message to add custom headers
                var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);

                // Add authentication using HMAC if auth key and worker URL are available
                if (!string.IsNullOrEmpty(_authKey) && !string.IsNullOrEmpty(_cloudflareWorkerUrl))
                {
                    // Generate HMAC token using the full request URL (which now includes timestamp)
                    var hmacToken = GenerateHmacToken(requestUrl);

                    // Add the HMAC token for authentication
                    request.Headers.Add("Worker-Token", hmacToken);

                    Console.WriteLine($"Added Worker-Token authentication header with HMAC and timestamp parameter: {timestamp}");
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