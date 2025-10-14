using System;
using System.Collections.Generic;
using System.Net;
using Xunit;

namespace Albatross.Tests
{
    /// <summary>
    /// Unit tests for IP range matching functionality
    /// Tests both IPv4 and IPv6 CIDR range matching for all cloud providers
    /// </summary>
    public class IpRangeTests
    {
        #region Helper Methods (copied from Home.razor for testing)
        
        private bool IsIpInRange(IPAddress ip, string cidrRange)
        {
            try
            {
                // Split CIDR range into IP and prefix length
                string[] parts = cidrRange.Split('/');
                if (parts.Length != 2)
                    return false;

                IPAddress networkAddress = IPAddress.Parse(parts[0]);
                int prefixLength = int.Parse(parts[1]);

                // Convert IP addresses to bytes for comparison
                byte[] ipBytes = ip.GetAddressBytes();
                byte[] networkBytes = networkAddress.GetAddressBytes();

                // Check if both IPs are the same version (IPv4 = 4 bytes, IPv6 = 16 bytes)
                if (ipBytes.Length != networkBytes.Length)
                    return false;

                // Validate prefix length based on IP version
                int maxPrefixLength = ipBytes.Length * 8; // 32 for IPv4, 128 for IPv6
                if (prefixLength < 0 || prefixLength > maxPrefixLength)
                    return false;

                // Calculate the number of full bytes and remaining bits to compare
                int numBytes = prefixLength / 8;
                int remainingBits = prefixLength % 8;

                // Compare full bytes
                for (int i = 0; i < numBytes && i < ipBytes.Length; i++)
                {
                    if (ipBytes[i] != networkBytes[i])
                        return false;
                }

                // Compare remaining bits in the next byte (if any)
                if (remainingBits > 0 && numBytes < ipBytes.Length)
                {
                    // Create a mask for the remaining bits
                    // For example, if remainingBits = 5, mask = 11111000 = 0xF8
                    int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                    
                    if ((ipBytes[numBytes] & mask) != (networkBytes[numBytes] & mask))
                        return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in IsIpInRange for CIDR '{cidrRange}': {ex.Message}");
                return false;
            }
        }
        
        #endregion

        #region IPv4 Tests

        [Fact]
        public void IPv4_BasicMatch_ShouldReturnTrue()
        {
            // Arrange
            var ip = IPAddress.Parse("192.168.1.100");
            var cidr = "192.168.1.0/24";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_NoMatch_ShouldReturnFalse()
        {
            // Arrange
            var ip = IPAddress.Parse("192.168.2.100");
            var cidr = "192.168.1.0/24";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void IPv4_AWS_EC2_Range_ShouldMatch()
        {
            // Arrange - Real AWS EC2 range from us-east-1
            var ip = IPAddress.Parse("3.5.140.1");
            var cidr = "3.5.140.0/22";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_AWS_S3_Range_ShouldMatch()
        {
            // Arrange - Real AWS S3 range
            var ip = IPAddress.Parse("52.216.0.100");
            var cidr = "52.216.0.0/15";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_Azure_Range_ShouldMatch()
        {
            // Arrange - Real Azure range
            var ip = IPAddress.Parse("13.64.0.10");
            var cidr = "13.64.0.0/11";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_GCP_Range_ShouldMatch()
        {
            // Arrange - Real GCP range
            var ip = IPAddress.Parse("34.64.0.100");
            var cidr = "34.64.0.0/10";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_Oracle_Range_ShouldMatch()
        {
            // Arrange - Real Oracle Cloud range
            var ip = IPAddress.Parse("129.213.0.50");
            var cidr = "129.213.0.0/16";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_EdgeCase_SingleHost_ShouldMatch()
        {
            // Arrange - /32 means single host
            var ip = IPAddress.Parse("8.8.8.8");
            var cidr = "8.8.8.8/32";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv4_EdgeCase_LargeNetwork_ShouldMatch()
        {
            // Arrange - /8 network (large range)
            var ip = IPAddress.Parse("10.255.255.255");
            var cidr = "10.0.0.0/8";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        #endregion

        #region IPv6 Tests

        [Fact]
        public void IPv6_BasicMatch_ShouldReturnTrue()
        {
            // Arrange
            var ip = IPAddress.Parse("2001:db8::1");
            var cidr = "2001:db8::/32";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_NoMatch_ShouldReturnFalse()
        {
            // Arrange
            var ip = IPAddress.Parse("2001:db9::1");
            var cidr = "2001:db8::/32";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void IPv6_AWS_CloudFront_Range_ShouldMatch()
        {
            // Arrange - Real AWS CloudFront IPv6 range
            var ip = IPAddress.Parse("2600:9000:5300::1");
            var cidr = "2600:9000:5300::/40";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_AWS_EC2_Range_ShouldMatch()
        {
            // Arrange - Real AWS EC2 IPv6 range from us-east-1
            var ip = IPAddress.Parse("2600:1f69:7400::100");
            var cidr = "2600:1f69:7400::/40";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_GCP_Range_ShouldMatch()
        {
            // Arrange - Real GCP IPv6 range
            var ip = IPAddress.Parse("2600:1900:8000::1");
            var cidr = "2600:1900:8000::/44";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_Azure_Range_ShouldMatch()
        {
            // Arrange - Real Azure IPv6 range
            var ip = IPAddress.Parse("2603:1030:100::1");
            var cidr = "2603:1030:100::/47";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_Google_DNS_ShouldMatch()
        {
            // Arrange - Google's public DNS IPv6
            var ip = IPAddress.Parse("2001:4860:4860::8888");
            var cidr = "2001:4860:4860::/48";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_EdgeCase_SingleHost_ShouldMatch()
        {
            // Arrange - /128 means single host
            var ip = IPAddress.Parse("2001:db8::1");
            var cidr = "2001:db8::1/128";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_EdgeCase_LargeNetwork_ShouldMatch()
        {
            // Arrange - /16 network (very large IPv6 range)
            var ip = IPAddress.Parse("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
            var cidr = "2001::/16";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IPv6_Compressed_Notation_ShouldMatch()
        {
            // Arrange - Test with compressed IPv6 notation
            var ip = IPAddress.Parse("2001:0db8:0000:0000:0000:0000:0000:0001");
            var cidr = "2001:db8::/32";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        #endregion

        #region Mixed Version Tests

        [Fact]
        public void MixedVersion_IPv4_Against_IPv6_Range_ShouldReturnFalse()
        {
            // Arrange
            var ipv4 = IPAddress.Parse("192.168.1.1");
            var ipv6Cidr = "2001:db8::/32";

            // Act
            var result = IsIpInRange(ipv4, ipv6Cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void MixedVersion_IPv6_Against_IPv4_Range_ShouldReturnFalse()
        {
            // Arrange
            var ipv6 = IPAddress.Parse("2001:db8::1");
            var ipv4Cidr = "192.168.1.0/24";

            // Act
            var result = IsIpInRange(ipv6, ipv4Cidr);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Boundary Tests

        [Fact]
        public void Boundary_IPv4_FirstAddress_ShouldMatch()
        {
            // Arrange - First address in range
            var ip = IPAddress.Parse("192.168.1.0");
            var cidr = "192.168.1.0/24";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Boundary_IPv4_LastAddress_ShouldMatch()
        {
            // Arrange - Last address in range
            var ip = IPAddress.Parse("192.168.1.255");
            var cidr = "192.168.1.0/24";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Boundary_IPv4_JustOutside_ShouldNotMatch()
        {
            // Arrange - Just outside the range
            var ip = IPAddress.Parse("192.168.2.0");
            var cidr = "192.168.1.0/24";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Boundary_IPv6_FirstAddress_ShouldMatch()
        {
            // Arrange - First address in range
            var ip = IPAddress.Parse("2001:db8::");
            var cidr = "2001:db8::/32";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Boundary_IPv6_LastAddress_ShouldMatch()
        {
            // Arrange - Last address in /32 range
            var ip = IPAddress.Parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff");
            var cidr = "2001:db8::/32";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.True(result);
        }

        #endregion

        #region Invalid Input Tests

        [Fact]
        public void Invalid_EmptyCidr_ShouldReturnFalse()
        {
            // Arrange
            var ip = IPAddress.Parse("192.168.1.1");
            var cidr = "";

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Invalid_MalformedCidr_ShouldReturnFalse()
        {
            // Arrange
            var ip = IPAddress.Parse("192.168.1.1");
            var cidr = "192.168.1.0";  // Missing /prefix

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Invalid_PrefixTooLarge_IPv4_ShouldReturnFalse()
        {
            // Arrange
            var ip = IPAddress.Parse("192.168.1.1");
            var cidr = "192.168.1.0/33";  // Max is 32 for IPv4

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Invalid_PrefixTooLarge_IPv6_ShouldReturnFalse()
        {
            // Arrange
            var ip = IPAddress.Parse("2001:db8::1");
            var cidr = "2001:db8::/129";  // Max is 128 for IPv6

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Real World Cloud Provider Test Cases

        [Theory]
        [InlineData("3.5.140.50", "3.5.140.0/22", true)]           // AWS EC2 us-east-1
        [InlineData("52.216.100.10", "52.216.0.0/15", true)]       // AWS S3
        [InlineData("13.64.50.100", "13.64.0.0/11", true)]         // Azure
        [InlineData("34.64.100.200", "34.64.0.0/10", true)]        // GCP
        [InlineData("192.168.1.1", "3.5.140.0/22", false)]         // Not in AWS range
        public void RealWorld_IPv4_CloudRanges(string ipStr, string cidr, bool expected)
        {
            // Arrange
            var ip = IPAddress.Parse(ipStr);

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("2600:9000:5300::1", "2600:9000:5300::/40", true)]           // AWS CloudFront
        [InlineData("2600:1f69:7400::1", "2600:1f69:7400::/40", true)]           // AWS EC2
        [InlineData("2600:1900:8000::1", "2600:1900:8000::/44", true)]           // GCP
        [InlineData("2603:1030:100::1", "2603:1030:100::/47", true)]             // Azure
        [InlineData("2001:4860:4860::8888", "2001:4860:4860::/48", true)]        // Google DNS
        [InlineData("2001:db8::1", "2600:9000:5300::/40", false)]                // Not in AWS range
        public void RealWorld_IPv6_CloudRanges(string ipStr, string cidr, bool expected)
        {
            // Arrange
            var ip = IPAddress.Parse(ipStr);

            // Act
            var result = IsIpInRange(ip, cidr);

            // Assert
            Assert.Equal(expected, result);
        }

        #endregion
    }
}
