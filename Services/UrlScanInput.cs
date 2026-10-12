using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Albatross.Services
{
    /// <summary>
    /// Client-side validation and encoding of URL scan targets.
    /// Mirrors the worker's rules (worker/url-scanner.js validateScanTarget) so users get
    /// immediate feedback; the worker re-validates everything server-side.
    /// </summary>
    public static class UrlScanInput
    {
        public const int MaxUrlLength = 2048;
        private static readonly int[] AllowedPorts = { 80, 443, 8080, 8443 };
        private static readonly string[] BlockedHostSuffixes = { ".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".arpa" };

        /// <summary>
        /// True when the input is meant as a URL (has an http/https scheme), as opposed to an IP address.
        /// </summary>
        public static bool LooksLikeUrl(string? input)
        {
            var value = input?.Trim() ?? string.Empty;
            return value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// True when the input looks like a bare domain or domain/path (e.g. "example.com/login"), so the UI can suggest adding a scheme.
        /// </summary>
        public static bool LooksLikeBareDomain(string? input)
        {
            var value = input?.Trim() ?? string.Empty;
            if (value.Length == 0 || value.Contains(' ') || LooksLikeUrl(value)) return false;
            var host = value.Split('/', '?', '#')[0].Split(':')[0];
            if (IPAddress.TryParse(host, out _)) return false;
            return host.Contains('.') && Uri.CheckHostName(host) == UriHostNameType.Dns && char.IsLetter(host[^1]);
        }

        /// <summary>
        /// Validates a URL for scanning.
        /// </summary>
        /// <param name="input">User input</param>
        /// <param name="normalizedUrl">Absolute URL string when valid</param>
        /// <param name="error">Human readable reason when invalid</param>
        public static bool TryValidate(string? input, out string normalizedUrl, out string error)
        {
            normalizedUrl = string.Empty;
            error = string.Empty;
            var value = input?.Trim() ?? string.Empty;

            if (value.Length == 0)
            {
                error = "Please enter a URL.";
                return false;
            }

            if (value.Length > MaxUrlLength)
            {
                error = $"URL is too long (maximum {MaxUrlLength} characters).";
                return false;
            }

            if (!LooksLikeUrl(value))
            {
                error = LooksLikeBareDomain(value)
                    ? $"URLs must include a scheme. Did you mean https://{value} ?"
                    : "Invalid URL. Enter a full http:// or https:// URL, e.g. https://example.com/login.";
                return false;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                error = "Invalid URL. Enter a full http:// or https:// URL, e.g. https://example.com/login.";
                return false;
            }

            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                error = "URLs containing a username or password are not allowed.";
                return false;
            }

            if (!uri.IsDefaultPort && Array.IndexOf(AllowedPorts, uri.Port) < 0)
            {
                error = "Only ports 80, 443, 8080 and 8443 can be scanned.";
                return false;
            }

            var host = uri.IdnHost.Trim('[', ']').TrimEnd('.').ToLowerInvariant();
            if (host == "localhost" || Array.Exists(BlockedHostSuffixes, s => host.EndsWith(s, StringComparison.Ordinal)))
            {
                error = "Local or internal hostnames cannot be scanned.";
                return false;
            }

            if (IPAddress.TryParse(host, out var ip))
            {
                if (!IsPublicIp(ip))
                {
                    error = "Private, loopback and reserved IP addresses cannot be scanned.";
                    return false;
                }
            }
            else if (!host.Contains('.'))
            {
                error = "Hostname must be a fully qualified domain name (e.g. example.com).";
                return false;
            }

            normalizedUrl = uri.AbsoluteUri;
            return true;
        }

        /// <summary>
        /// Encodes a URL as unpadded base64url (RFC 4648 §5) for transport in the worker query string.
        /// base64url only uses [A-Za-z0-9-_], so no further escaping is needed.
        /// </summary>
        public static string ToBase64Url(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        /// <summary>
        /// Decodes an unpadded base64url string (used by tests and for round-tripping).
        /// </summary>
        public static string FromBase64Url(string value)
        {
            var b64 = value.Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }

        private static bool IsPublicIp(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var b = ip.GetAddressBytes();

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 0 || b[0] == 10 || b[0] == 127) return false;
                if (b[0] == 100 && (b[1] & 0xC0) == 64) return false;
                if (b[0] == 169 && b[1] == 254) return false;
                if (b[0] == 172 && (b[1] & 0xF0) == 16) return false;
                if (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) return false;
                if (b[0] == 192 && b[1] == 88 && b[2] == 99) return false;
                if (b[0] == 192 && b[1] == 168) return false;
                if (b[0] == 198 && (b[1] & 0xFE) == 18) return false;
                if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;
                if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
                if (b[0] >= 224) return false;
                return true;
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (ip.Equals(IPAddress.IPv6Loopback) || ip.Equals(IPAddress.IPv6Any)) return false;
                if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return false;
                if ((b[0] & 0xFE) == 0xFC) return false;
                if (b[0] == 0xFF) return false;
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false;
                return true;
            }

            return false;
        }
    }
}
