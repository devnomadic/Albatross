using Albatross.Services;
using Xunit;

namespace Albatross.Tests
{
    /// <summary>
    /// Tests for client-side URL scan input validation and base64url encoding.
    /// </summary>
    public class UrlScanInputTests
    {
        [Theory]
        [InlineData("https://example.com")]
        [InlineData("http://example.com/login?next=/admin")]
        [InlineData("HTTPS://Example.COM/Path")]
        [InlineData("https://sub.example.co.uk:8443/x#frag")]
        [InlineData("https://8.8.8.8/")]
        [InlineData("https://[2001:4860:4860::8888]/")]
        [InlineData("  https://example.com  ")]
        public void TryValidate_AcceptsWellFormedPublicUrls(string input)
        {
            Assert.True(UrlScanInput.TryValidate(input, out var normalized, out var error), error);
            Assert.StartsWith("http", normalized);
        }

        [Theory]
        [InlineData("", "Please enter a URL")]
        [InlineData("example.com", "Did you mean https://example.com")]
        [InlineData("ftp://example.com", "Invalid URL")]
        [InlineData("javascript:alert(1)", "Invalid URL")]
        [InlineData("https://", "Invalid URL")]
        [InlineData("https://user:pass@example.com", "username or password")]
        [InlineData("https://example.com:22/", "ports")]
        [InlineData("http://localhost:8080/", "Local or internal")]
        [InlineData("http://printer.local/", "Local or internal")]
        [InlineData("http://127.0.0.1/", "Private")]
        [InlineData("http://10.0.0.5/", "Private")]
        [InlineData("http://192.168.1.1/", "Private")]
        [InlineData("http://169.254.169.254/latest/meta-data", "Private")]
        [InlineData("http://[::1]/", "Private")]
        [InlineData("http://[fd00::1]/", "Private")]
        [InlineData("https://intranet/", "fully qualified")]
        public void TryValidate_RejectsInvalidOrUnsafeUrls(string input, string expectedMessageFragment)
        {
            Assert.False(UrlScanInput.TryValidate(input, out _, out var error));
            Assert.Contains(expectedMessageFragment, error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void TryValidate_RejectsOverlongUrls()
        {
            var url = "https://example.com/" + new string('a', UrlScanInput.MaxUrlLength);
            Assert.False(UrlScanInput.TryValidate(url, out _, out var error));
            Assert.Contains("too long", error);
        }

        [Theory]
        [InlineData("https://example.com", true)]
        [InlineData("HTTP://example.com", true)]
        [InlineData("8.8.8.8", false)]
        [InlineData("8.8.8.8;60", false)]
        [InlineData("2001:4860:4860::8888", false)]
        [InlineData("example.com", false)]
        public void LooksLikeUrl_DistinguishesUrlsFromIps(string input, bool expected)
        {
            Assert.Equal(expected, UrlScanInput.LooksLikeUrl(input));
        }

        [Theory]
        [InlineData("example.com", true)]
        [InlineData("www.example.com/login", true)]
        [InlineData("8.8.8.8", false)]
        [InlineData("8.8.8.8;60", false)]
        [InlineData("not a domain", false)]
        public void LooksLikeBareDomain_DetectsMissingScheme(string input, bool expected)
        {
            Assert.Equal(expected, UrlScanInput.LooksLikeBareDomain(input));
        }

        [Theory]
        [InlineData("https://example.com/", "aHR0cHM6Ly9leGFtcGxlLmNvbS8")]
        [InlineData("https://example.com/?a=1", "aHR0cHM6Ly9leGFtcGxlLmNvbS8_YT0x")]
        public void ToBase64Url_ProducesUnpaddedUrlSafeOutput(string input, string expected)
        {
            var encoded = UrlScanInput.ToBase64Url(input);
            Assert.Equal(expected, encoded);
            Assert.DoesNotContain('=', encoded);
            Assert.DoesNotContain('+', encoded);
            Assert.DoesNotContain('/', encoded);
        }

        [Theory]
        [InlineData("https://example.com/")]
        [InlineData("https://例え.jp/パス?q=ü&x=~")]
        [InlineData("https://example.com/a?b=c&d=e+f/g")]
        public void Base64Url_RoundTrips(string input)
        {
            Assert.Equal(input, UrlScanInput.FromBase64Url(UrlScanInput.ToBase64Url(input)));
        }
    }
}
