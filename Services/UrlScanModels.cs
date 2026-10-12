using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Albatross.Services
{
    /// <summary>
    /// URL scan response from the Cloudflare Worker (worker/url-scanner.js).
    /// </summary>
    public class UrlScanResponse
    {
        [JsonPropertyName("scanType")] public string? ScanType { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("details")] public string? Details { get; set; }
        [JsonPropertyName("input")] public UrlScanInputInfo? Input { get; set; }
        [JsonPropertyName("target")] public UrlScanTarget? Target { get; set; }
        [JsonPropertyName("summary")] public UrlScanSummary? Summary { get; set; }
        [JsonPropertyName("redirects")] public UrlScanRedirects? Redirects { get; set; }
        [JsonPropertyName("http")] public UrlScanHttp? Http { get; set; }
        [JsonPropertyName("tls")] public UrlScanTls? Tls { get; set; }
        [JsonPropertyName("domain")] public UrlScanDomain? Domain { get; set; }
        [JsonPropertyName("network")] public UrlScanNetwork? Network { get; set; }
        [JsonPropertyName("technologies")] public List<UrlScanTechnology>? Technologies { get; set; }
        [JsonPropertyName("content")] public UrlScanContent? Content { get; set; }
        [JsonPropertyName("securityTxt")] public UrlScanSecurityTxt? SecurityTxt { get; set; }
        [JsonPropertyName("screenshot")] public UrlScanScreenshot? Screenshot { get; set; }
        [JsonPropertyName("findings")] public List<UrlScanFinding>? Findings { get; set; }
        [JsonPropertyName("aiAssessment")] public UrlScanAiAssessment? AiAssessment { get; set; }
        [JsonPropertyName("workerInfo")] public WorkerInfo? WorkerInfo { get; set; }
    }

    public class UrlScanInputInfo
    {
        [JsonPropertyName("raw")] public string? Raw { get; set; }
        [JsonPropertyName("encoding")] public string? Encoding { get; set; }
        [JsonPropertyName("url")] public string? Url { get; set; }
    }

    public class UrlScanTarget
    {
        [JsonPropertyName("url")] public string? Url { get; set; }
        [JsonPropertyName("scheme")] public string? Scheme { get; set; }
        [JsonPropertyName("hostname")] public string? Hostname { get; set; }
        [JsonPropertyName("port")] public string? Port { get; set; }
        [JsonPropertyName("registrableDomain")] public string? RegistrableDomain { get; set; }
    }

    public class UrlScanSummary
    {
        [JsonPropertyName("finalUrl")] public string? FinalUrl { get; set; }
        [JsonPropertyName("statusCode")] public int? StatusCode { get; set; }
        [JsonPropertyName("title")] public string? Title { get; set; }
        [JsonPropertyName("contentType")] public string? ContentType { get; set; }
        [JsonPropertyName("fetchError")] public string? FetchError { get; set; }
        [JsonPropertyName("securityScore")] public int? SecurityScore { get; set; }
        [JsonPropertyName("riskLevel")] public string? RiskLevel { get; set; }
        [JsonPropertyName("findingCounts")] public Dictionary<string, int>? FindingCounts { get; set; }
        [JsonPropertyName("durationMs")] public long? DurationMs { get; set; }
    }

    public class UrlScanRedirects
    {
        [JsonPropertyName("count")] public int Count { get; set; }
        [JsonPropertyName("chain")] public List<UrlScanRedirectHop>? Chain { get; set; }
        [JsonPropertyName("crossDomain")] public bool CrossDomain { get; set; }
        [JsonPropertyName("httpsDowngrade")] public bool HttpsDowngrade { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    public class UrlScanRedirectHop
    {
        [JsonPropertyName("url")] public string? Url { get; set; }
        [JsonPropertyName("statusCode")] public int StatusCode { get; set; }
        [JsonPropertyName("statusText")] public string? StatusText { get; set; }
        [JsonPropertyName("location")] public string? Location { get; set; }
        [JsonPropertyName("server")] public string? Server { get; set; }
        [JsonPropertyName("timeMs")] public long? TimeMs { get; set; }
        [JsonPropertyName("httpsDowngrade")] public bool? HttpsDowngrade { get; set; }
        [JsonPropertyName("crossDomain")] public bool? CrossDomain { get; set; }
    }

    public class UrlScanHttp
    {
        [JsonPropertyName("versions")] public Dictionary<string, bool?>? Versions { get; set; }
        [JsonPropertyName("evidence")] public List<string>? Evidence { get; set; }
        [JsonPropertyName("httpsEnforcement")] public UrlScanHttpsEnforcement? HttpsEnforcement { get; set; }
        [JsonPropertyName("headers")] public Dictionary<string, string>? Headers { get; set; }
        [JsonPropertyName("securityHeaders")] public List<UrlScanSecurityHeader>? SecurityHeaders { get; set; }
        [JsonPropertyName("cookies")] public List<UrlScanCookie>? Cookies { get; set; }
    }

    public class UrlScanHttpsEnforcement
    {
        [JsonPropertyName("checked")] public bool Checked { get; set; }
        [JsonPropertyName("statusCode")] public int? StatusCode { get; set; }
        [JsonPropertyName("location")] public string? Location { get; set; }
        [JsonPropertyName("enforced")] public bool? Enforced { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    public class UrlScanSecurityHeader
    {
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("status")] public string? Status { get; set; }
        [JsonPropertyName("value")] public string? Value { get; set; }
        [JsonPropertyName("note")] public string? Note { get; set; }
    }

    public class UrlScanCookie
    {
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("secure")] public bool Secure { get; set; }
        [JsonPropertyName("httpOnly")] public bool HttpOnly { get; set; }
        [JsonPropertyName("sameSite")] public string? SameSite { get; set; }
        [JsonPropertyName("issues")] public List<string>? Issues { get; set; }
    }

    public class UrlScanTls
    {
        [JsonPropertyName("probed")] public bool Probed { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("versions")] public Dictionary<string, bool>? Versions { get; set; }
        [JsonPropertyName("preferredCipher")] public string? PreferredCipher { get; set; }
        [JsonPropertyName("tls12Cipher")] public string? Tls12Cipher { get; set; }
        [JsonPropertyName("alpn")] public string? Alpn { get; set; }
        [JsonPropertyName("certificate")] public UrlScanCertificate? Certificate { get; set; }
        [JsonPropertyName("chain")] public List<UrlScanChainCert>? Chain { get; set; }
        [JsonPropertyName("certificateNote")] public string? CertificateNote { get; set; }
    }

    public class UrlScanCertificate
    {
        [JsonPropertyName("subject")] public Dictionary<string, string>? Subject { get; set; }
        [JsonPropertyName("subjectString")] public string? SubjectString { get; set; }
        [JsonPropertyName("issuer")] public Dictionary<string, string>? Issuer { get; set; }
        [JsonPropertyName("issuerString")] public string? IssuerString { get; set; }
        [JsonPropertyName("validFrom")] public string? ValidFrom { get; set; }
        [JsonPropertyName("validTo")] public string? ValidTo { get; set; }
        [JsonPropertyName("daysRemaining")] public int? DaysRemaining { get; set; }
        [JsonPropertyName("expired")] public bool Expired { get; set; }
        [JsonPropertyName("signatureAlgorithm")] public string? SignatureAlgorithm { get; set; }
        [JsonPropertyName("keyAlgorithm")] public string? KeyAlgorithm { get; set; }
        [JsonPropertyName("keySize")] public int? KeySize { get; set; }
        [JsonPropertyName("subjectAltNames")] public List<string>? SubjectAltNames { get; set; }
        [JsonPropertyName("selfSigned")] public bool SelfSigned { get; set; }
        [JsonPropertyName("hostnameMatch")] public bool? HostnameMatch { get; set; }
        [JsonPropertyName("chainLength")] public int? ChainLength { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    public class UrlScanChainCert
    {
        [JsonPropertyName("subject")] public string? Subject { get; set; }
        [JsonPropertyName("issuer")] public string? Issuer { get; set; }
        [JsonPropertyName("validTo")] public string? ValidTo { get; set; }
    }

    public class UrlScanDomain
    {
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("registration")] public UrlScanRegistration? Registration { get; set; }
        [JsonPropertyName("dns")] public UrlScanDns? Dns { get; set; }
    }

    public class UrlScanRegistration
    {
        [JsonPropertyName("success")] public bool Success { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("domain")] public string? Domain { get; set; }
        [JsonPropertyName("created")] public string? Created { get; set; }
        [JsonPropertyName("expires")] public string? Expires { get; set; }
        [JsonPropertyName("updated")] public string? Updated { get; set; }
        [JsonPropertyName("ageDays")] public int? AgeDays { get; set; }
        [JsonPropertyName("daysUntilExpiry")] public int? DaysUntilExpiry { get; set; }
        [JsonPropertyName("registrar")] public string? Registrar { get; set; }
        [JsonPropertyName("status")] public List<string>? Status { get; set; }
        [JsonPropertyName("nameservers")] public List<string>? Nameservers { get; set; }
    }

    public class UrlScanDns
    {
        [JsonPropertyName("skipped")] public bool Skipped { get; set; }
        [JsonPropertyName("a")] public List<string>? A { get; set; }
        [JsonPropertyName("aaaa")] public List<string>? Aaaa { get; set; }
        [JsonPropertyName("cname")] public List<string>? Cname { get; set; }
        [JsonPropertyName("ns")] public List<string>? Ns { get; set; }
        [JsonPropertyName("mx")] public List<string>? Mx { get; set; }
        [JsonPropertyName("caa")] public List<string>? Caa { get; set; }
        [JsonPropertyName("httpsRecordAlpn")] public List<string>? HttpsRecordAlpn { get; set; }
        [JsonPropertyName("spf")] public string? Spf { get; set; }
        [JsonPropertyName("dmarc")] public string? Dmarc { get; set; }
        [JsonPropertyName("dnssec")] public bool? Dnssec { get; set; }
    }

    public class UrlScanNetwork
    {
        [JsonPropertyName("ips")] public List<UrlScanIp>? Ips { get; set; }
        [JsonPropertyName("cdn")] public UrlScanCdn? Cdn { get; set; }
    }

    public class UrlScanIp
    {
        [JsonPropertyName("ip")] public string? Ip { get; set; }
        [JsonPropertyName("version")] public int Version { get; set; }
        [JsonPropertyName("asn")] public long? Asn { get; set; }
        [JsonPropertyName("asnName")] public string? AsnName { get; set; }
        [JsonPropertyName("asnOrg")] public string? AsnOrg { get; set; }
        [JsonPropertyName("country")] public string? Country { get; set; }
        [JsonPropertyName("abuseConfidenceScore")] public int? AbuseConfidenceScore { get; set; }
        [JsonPropertyName("abuseTotalReports")] public int? AbuseTotalReports { get; set; }
        [JsonPropertyName("isp")] public string? Isp { get; set; }
        [JsonPropertyName("usageType")] public string? UsageType { get; set; }
    }

    public class UrlScanCdn
    {
        [JsonPropertyName("detected")] public bool Detected { get; set; }
        [JsonPropertyName("providers")] public List<UrlScanCdnProvider>? Providers { get; set; }
        [JsonPropertyName("cacheStatus")] public string? CacheStatus { get; set; }
    }

    public class UrlScanCdnProvider
    {
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("evidence")] public List<string>? Evidence { get; set; }
    }

    public class UrlScanTechnology
    {
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("category")] public string? Category { get; set; }
        [JsonPropertyName("version")] public string? Version { get; set; }
        [JsonPropertyName("sources")] public List<string>? Sources { get; set; }
        [JsonPropertyName("evidence")] public List<string>? Evidence { get; set; }
        [JsonPropertyName("vulnerabilities")] public List<UrlScanVulnerability>? Vulnerabilities { get; set; }
    }

    public class UrlScanVulnerability
    {
        [JsonPropertyName("severity")] public string? Severity { get; set; }
        [JsonPropertyName("advisories")] public List<string>? Advisories { get; set; }
        [JsonPropertyName("note")] public string? Note { get; set; }
    }

    public class UrlScanContent
    {
        [JsonPropertyName("title")] public string? Title { get; set; }
        [JsonPropertyName("scripts")] public UrlScanScripts? Scripts { get; set; }
        [JsonPropertyName("mixedContent")] public List<string>? MixedContent { get; set; }
        [JsonPropertyName("insecureForms")] public List<string>? InsecureForms { get; set; }
        [JsonPropertyName("thirdPartyScriptHosts")] public List<string>? ThirdPartyScriptHosts { get; set; }
        [JsonPropertyName("renderedThirdPartyHosts")] public List<UrlScanHostCount>? RenderedThirdPartyHosts { get; set; }
    }

    public class UrlScanScripts
    {
        [JsonPropertyName("total")] public int Total { get; set; }
        [JsonPropertyName("external")] public int External { get; set; }
        [JsonPropertyName("withoutSri")] public List<string>? WithoutSri { get; set; }
    }

    public class UrlScanHostCount
    {
        [JsonPropertyName("host")] public string? Host { get; set; }
        [JsonPropertyName("requests")] public int Requests { get; set; }
    }

    public class UrlScanSecurityTxt
    {
        [JsonPropertyName("present")] public bool Present { get; set; }
        [JsonPropertyName("url")] public string? Url { get; set; }
    }

    public class UrlScanScreenshot
    {
        [JsonPropertyName("success")] public bool Success { get; set; }
        [JsonPropertyName("image")] public string? Image { get; set; }
        [JsonPropertyName("width")] public int? Width { get; set; }
        [JsonPropertyName("height")] public int? Height { get; set; }
        [JsonPropertyName("finalUrl")] public string? FinalUrl { get; set; }
        [JsonPropertyName("navigationWarning")] public string? NavigationWarning { get; set; }
        [JsonPropertyName("requestCount")] public int? RequestCount { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    public class UrlScanFinding
    {
        [JsonPropertyName("severity")] public string? Severity { get; set; }
        [JsonPropertyName("category")] public string? Category { get; set; }
        [JsonPropertyName("title")] public string? Title { get; set; }
        [JsonPropertyName("detail")] public string? Detail { get; set; }
    }

    public class UrlScanAiAssessment
    {
        [JsonPropertyName("success")] public bool Success { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("model")] public string? Model { get; set; }
        [JsonPropertyName("analysis")] public UrlScanAiAnalysis? Analysis { get; set; }
    }

    /// <summary>
    /// AI output is model-generated, so fields are read loosely (JsonElement) to avoid a
    /// malformed value (e.g. "85/100" or an object instead of a string) failing the whole scan.
    /// </summary>
    public class UrlScanAiAnalysis
    {
        [JsonPropertyName("riskLevel")] public JsonElement RiskLevel { get; set; }
        [JsonPropertyName("securityScore")] public JsonElement SecurityScore { get; set; }
        [JsonPropertyName("summary")] public JsonElement Summary { get; set; }
        [JsonPropertyName("phishingLikelihood")] public JsonElement PhishingLikelihood { get; set; }
        [JsonPropertyName("keyRisks")] public JsonElement KeyRisks { get; set; }
        [JsonPropertyName("recommendations")] public JsonElement Recommendations { get; set; }

        public static string? AsText(JsonElement e) => e.ValueKind switch
        {
            JsonValueKind.String => e.GetString(),
            JsonValueKind.Undefined or JsonValueKind.Null => null,
            _ => e.GetRawText()
        };

        public static List<string> AsList(JsonElement e)
        {
            var list = new List<string>();
            if (e.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in e.EnumerateArray())
                {
                    var text = AsText(item);
                    if (!string.IsNullOrWhiteSpace(text)) list.Add(text);
                }
            }
            else if (AsText(e) is { Length: > 0 } single)
            {
                list.Add(single);
            }
            return list;
        }

        public int? ScoreValue => SecurityScore.ValueKind == JsonValueKind.Number && SecurityScore.TryGetInt32(out var n)
            ? n
            : int.TryParse(AsText(SecurityScore)?.Split('/')[0].Trim(), out var parsed) ? parsed : null;
    }

    /// <summary>
    /// Typed scan result plus the raw JSON (for the JSON tree viewer).
    /// </summary>
    public class UrlScanResult
    {
        public UrlScanResponse Response { get; init; } = new();
        public string RawJson { get; init; } = string.Empty;
    }
}
