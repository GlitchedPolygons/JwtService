using System;
using System.Linq;
using System.Threading.Tasks;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

using Microsoft.IdentityModel.Tokens;

using Xunit;

namespace GlitchedPolygons.Services.JwtService.UnitTests
{
    [SuppressMessage("ReSharper", "EnforceIfStatementBraces")]
    public class JwtServiceTests : IDisposable
    {
        private readonly SecureString key;
        private const string CHARS = "$%#@!*-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        public JwtServiceTests()
        {
            key = new SecureString();
            for (int i = 0; i < 128; i++)
            {
                var random = new Random();
                key.AppendChar(CHARS[random.Next(0, CHARS.Length - 1)]);
            }
        }

        public void Dispose()
        {
            key.Dispose();
        }

        [Fact]
        public void Ctor_NullOrEmptyKey_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new JwtService(string.Empty));
            Assert.Throws<ArgumentException>(() => new JwtService(new SecureString()));
        }

        [Fact]
        public void GenerateToken_ValidParams_ShouldNotFail()
        {
            var jwt = new JwtService(key);
            var token = jwt.GenerateToken();
            Assert.False(string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token));
        }

        [Fact]
        public async Task GenerateToken_Expired_ShouldFailToValidate()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.Zero);
            var token = jwt.GenerateToken(lifetime: TimeSpan.FromMilliseconds(250));

            await Task.Delay(750);
            var result = jwt.ValidateToken(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
            Assert.IsType<SecurityTokenExpiredException>(result.Exception);
        }

        [Fact]
        public async Task GenerateToken_NotYetValid_ShouldFailToValidate()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.Zero);
            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromMilliseconds(6000),
                notBefore: DateTime.UtcNow.AddMilliseconds(1500)
            );

            var result = jwt.ValidateToken(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
            Assert.IsType<SecurityTokenNotYetValidException>(result.Exception);

            await Task.Delay(2500);
            result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.NotNull(result.ValidatedToken);
            Assert.Null(result.ErrorMessage);
        }

        [Fact]
        public void GenerateToken_NotUsingUTCforNotBeforeParam_ShouldThrowArgumentExceptionWhenTryingToGenerateToken()
        {
            // Same as the test above, except DateTime.Now is used as notBefore argument inside GenerateToken(...).
            // Absolutely make ALWAYS sure that your 'notBefore' parameter is > DateTime.UtcNow!
            var jwt = new JwtService(key, clockSkew: TimeSpan.Zero);

            Assert.ThrowsAny<ArgumentException>(() =>
                {
                    var token = jwt.GenerateToken(
                        lifetime: TimeSpan.FromSeconds(3),
                        notBefore: new DateTime(int.MaxValue - 1, 10, 10, 10, 10, 10, DateTimeKind.Local)
                    );
                }
            );
        }

        [Fact]
        public async Task GenerateToken_ValidateLifetimeEnabledToken_IsStillAlive_ShouldSucceedValidation()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.Zero);

            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromSeconds(6.0d)
            );

            await Task.Delay(2500);
            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.Null(result.Exception);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }

        [Fact]
        public async Task GenerateToken_ValidateLifetimeEnabledTokenWithNotBeforeParamSet_IsStillAlive_ShouldSucceedValidation()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.Zero);

            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromMilliseconds(6000),
                notBefore: DateTime.UtcNow.AddMilliseconds(2000)
            );

            await Task.Delay(4000);
            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.Null(result.Exception);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void ValidateToken_NullOrEmptyJwt_ThrowsArgumentException(string jwt)
        {
            Assert.Throws<ArgumentException>(() => new JwtService(key).ValidateToken(jwt));
        }

        [Fact]
        public void ValidateToken_ValidationParametersWithNullIssuerSigningKey_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new JwtService(key).ValidateToken("jwt", new TokenValidationParameters()));
        }

        [Fact]
        public void GenerateToken_ValidateAgainstSingleIssuer_ShouldSucceed()
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                issuers: new[] { "issuer" }
            );

            var token = jwt.GenerateToken(
                issuer: "issuer"
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.Null(result.Exception);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }

        [Theory]
        [InlineData("issuer_1")]
        [InlineData("issuer_2")]
        [InlineData("issuer_3")]
        [InlineData("issuer_4")]
        [InlineData("issuer_5")]
        public void GenerateToken_ValidateAgainstMultipleIssuers_ShouldSucceed(string issuer)
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                issuers: new[] { "issuer_1", "issuer_2", "issuer_3", "issuer_4", "issuer_5" }
            );

            var token = jwt.GenerateToken(
                issuer: issuer
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.Null(result.Exception);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("bad_guy")]
        public void GenerateToken_ValidateInvalidIssuerAgainstSingleIssuer_ShouldFail(string issuer)
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                issuers: new[] { "issuer" }
            );

            var token = jwt.GenerateToken(
                issuer: issuer
            );

            var result = jwt.ValidateToken(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
            Assert.IsType<SecurityTokenInvalidIssuerException>(result.Exception);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("bad_guy")]
        public void GenerateToken_ValidateInvalidIssuerAgainstMultipleIssuers_ShouldFail(string issuer)
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                issuers: new[] { "issuer_1", "issuer_2", "issuer_3", "issuer_4", "issuer_5" }
            );

            var token = jwt.GenerateToken(
                issuer: issuer
            );

            var result = jwt.ValidateToken(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
            Assert.IsType<SecurityTokenInvalidIssuerException>(result.Exception);
        }

        [Theory]
        [InlineData("claim", "lame")]
        [InlineData("user", "admin")]
        public void GenerateToken_ValidateSingleClaim_ShouldSucceed(string type, string value)
        {
            var jwt = new JwtService(key,
                validateLifetime: false
            );

            var claim = new Claim(type, value);

            var token = jwt.GenerateToken(
                claims: new[] { claim }
            );

            var result = jwt.ValidateToken(token).ValidatedToken.Item1.Claims.ToArray()[0];

            Assert.True(result.Type == claim.Type && result.Value == claim.Value && result.ValueType == claim.ValueType);
        }

        [Fact]
        public void GenerateToken_ValidateMultipleClaims_ShouldSucceed()
        {
            var jwt = new JwtService(key,
                validateLifetime: false
            );

            var claims = new[]
            {
                new Claim("claim1", "value1"),
                new Claim("claim2", "value2"),
                new Claim("claim3", "value3"),
            };

            var token = jwt.GenerateToken(
                claims: claims
            );

            foreach (var claim in jwt.ValidateToken(token).ValidatedToken.Item1.Claims)
            {
                Assert.Contains(claims,
                    c => c.Type == claim.Type
                    && c.Value == claim.Value
                    && c.ValueType == claim.ValueType
                );
            }
        }

        [Fact]
        public void GenerateToken_ValidateAgainstSingleAudience_ShouldSucceed()
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                audiences: new[] { "single_audience" }
            );

            var token = jwt.GenerateToken(
                audience: "single_audience"
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.Null(result.Exception);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }

        [Theory]
        [InlineData("audience1")]
        [InlineData("audience2")]
        [InlineData("audience3")]
        public void GenerateToken_ValidateAgainstMultipleAudiences_ShouldSucceed(string audience)
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                audiences: new[] { "audience1", "audience2", "audience3" }
            );

            var token = jwt.GenerateToken(
                audience: audience
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);
            Assert.Null(result.Exception);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("bad_audience")]
        public void GenerateToken_ValidateInvalidAudienceAgainstSingleAudience_ShouldFail(string audience)
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                audiences: new[] { "single_audience" }
            );

            var token = jwt.GenerateToken(
                audience: audience
            );

            var result = jwt.ValidateToken(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
            Assert.IsType<SecurityTokenInvalidAudienceException>(result.Exception);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("bad_audience")]
        public void GenerateToken_ValidateInvalidAudienceAgainstMultipleAudiences_ShouldFail(string audience)
        {
            var jwt = new JwtService(key,
                validateLifetime: false,
                audiences: new[] { "audience1", "audience2", "audience3" }
            );

            var token = jwt.GenerateToken(
                audience: audience
            );

            var result = jwt.ValidateToken(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
            Assert.IsType<SecurityTokenInvalidAudienceException>(result.Exception);
        }

        [Fact]
        public void JwtValidationResultIndexer_RetrieveSingleClaim_ShouldSucceed()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.FromMinutes(3));

            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromHours(1),
                claims: new[] { new Claim("single_claim_key", "single_claim_value") }
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);

            var claim = result["single_claim_key"];

            Assert.NotNull(claim);
            Assert.Equal("single_claim_key", claim.Type);
            Assert.Equal("single_claim_value", claim.Value);
        }

        [Fact]
        public void JwtValidationResultIndexer_RetrieveMultipleClaims_ShouldSucceed()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.FromMinutes(3));

            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromHours(1),
                claims: new[] { new Claim("claim1", "value1"), new Claim("claim2", "value2"), new Claim("claim3", "value3") }
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);

            var claim1 = result["claim1"];
            var claim2 = result["claim2"];
            var claim3 = result["claim3"];

            Assert.NotNull(claim1);
            Assert.NotNull(claim2);
            Assert.NotNull(claim3);

            Assert.Equal("claim1", claim1.Type);
            Assert.Equal("value1", claim1.Value);

            Assert.Equal("claim2", claim2.Type);
            Assert.Equal("value2", claim2.Value);

            Assert.Equal("claim3", claim3.Type);
            Assert.Equal("value3", claim3.Value);
        }

        [Fact]
        public void JwtValidationResultIndexer_RetrieveInexistentSingleClaim_ShouldFail()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.FromMinutes(3));

            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromHours(1),
                claims: null
            );

            var result = jwt.ValidateToken(token);

            Assert.True(result.Successful);

            var claim = result["single_claim_key"];

            Assert.Null(claim);
        }

        [Fact]
        public void GenerateToken_OnlyPublicKeyProvided_ShouldFail()
        {
            using (var rsa = RSA.Create(4096))
            {
                var jwt = new JwtService(rsa.ExportParameters(false));
                Assert.Throws<ArgumentException>(() => { jwt.GenerateToken(); });
            }
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void GenerateAsymmetricJwtCorrectly_ShouldSucceed(int keySize)
        {
            using (var rsa = RSA.Create(keySize))
            {
                var jwt = new JwtService(rsa.ExportParameters(true));
                var token = jwt.GenerateToken();
                Assert.False(string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token));
            }
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void GenerateAsymmetricJwtCorrectly_ValidationShouldAlsoSucceed(int keySize)
        {
            using (var rsa = RSA.Create(keySize))
            {
                var jwt = new JwtService(rsa.ExportParameters(true));
                var validator = new JwtService(rsa.ExportParameters(false));

                var token = jwt.GenerateToken(lifetime: TimeSpan.FromMinutes(10));
                var result = validator.ValidateToken(token);

                Assert.True(result.Successful);
                Assert.NotNull(result.ValidatedToken);
            }
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void GenerateAsymmetricJwtCorrectly_ValidationShouldSucceed_ClaimsShouldMatch(int keySize)
        {
            using (var rsa = RSA.Create(keySize))
            {
                var jwt = new JwtService(rsa.ExportParameters(true));
                var validator = new JwtService(rsa.ExportParameters(false), validateLifetime: false);

                var token = jwt.GenerateToken(claims: new[] { new Claim("claim1", "value1"), new Claim("claim2", "value2") });
                var result = validator.ValidateToken(token);

                Assert.True(result.Successful);
                Assert.NotNull(result.ValidatedToken);
                Assert.Equal("value1", result["claim1"].Value);
                Assert.Equal("value2", result["claim2"].Value);
                Assert.Null(result["claim0"]);
            }
        }

        [Theory]
        [InlineData(-420)]
        [InlineData(1024)]
        [InlineData(32768)]
        public void GenerateAsymmetricJwt_InstantiateServiceWithWrongKeySize_ShouldThrowException(int wrongKeySize)
        {
            Assert.ThrowsAny<Exception>(() =>
            {
                using (var rsa = RSA.Create(wrongKeySize))
                {
                    var jwt = new JwtService(rsa.ExportParameters(true));
                    var token = jwt.GenerateToken();
                    Assert.True(string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token));
                }
            });
        }

        [Fact]
        public void GenerateAsymmetricJwt_ValidateWithWrongKeySize_ShouldFail()
        {
            var rsa2048 = RSA.Create(2048);
            var rsa4096 = RSA.Create(4096);

            var jwt4096 = new JwtService(rsa4096.ExportParameters(true));
            var token = jwt4096.GenerateToken(lifetime: TimeSpan.FromMinutes(10));

            var jwt4096_pub = new JwtService(rsa4096.ExportParameters(false));
            var control = jwt4096_pub.ValidateToken(token);
            Assert.True(control.Successful);

            var jwt2048 = new JwtService(rsa2048.ExportParameters(false));
            var result = jwt2048.ValidateToken(token);

            Assert.False(result.Successful);

            rsa2048.Dispose(); rsa4096.Dispose();
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void GenerateAsymmetricJwt_ValidateWithWrongKeyOfSameSize_ShouldFail(int keySize)
        {
            var rsa1 = RSA.Create(keySize);
            var rsa2 = RSA.Create(keySize);

            var jwt1 = new JwtService(rsa1.ExportParameters(true));
            var token = jwt1.GenerateToken(lifetime: TimeSpan.FromMinutes(10));

            var jwt1_pub = new JwtService(rsa1.ExportParameters(false));
            var control = jwt1_pub.ValidateToken(token);
            Assert.True(control.Successful);

            var jwt2 = new JwtService(rsa2.ExportParameters(false));
            var result = jwt2.ValidateToken(token);

            Assert.False(result.Successful);

            rsa1.Dispose(); rsa2.Dispose();
        }

        [Fact]
        public void GenerateAsymmetricJwt_ValidateTamperedToken_ShouldFail()
        {
            using (var rsa = RSA.Create(4096))
            {
                var jwt = new JwtService(rsa.ExportParameters(true));
                var token = jwt.GenerateToken();

                var tokenChars = token.ToCharArray();
                for (int i = 0; i < tokenChars.Length; i++)
                {
                    if (new Random().NextDouble() > 0.9d)
                    {
                        tokenChars[i] = 'x';
                    }
                }

                token = new string(tokenChars);
                var result = jwt.ValidateToken(token);

                Assert.False(result.Successful);
                Assert.Null(result.ValidatedToken);
            }
        }
    }
}
