using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace GlitchedPolygons.Services.JwtService.UnitTests
{
    [SuppressMessage("ReSharper", "EnforceIfStatementBraces")]
    public class JwtServiceTests : IDisposable
    {
        readonly SecureString key;
        const string CHARS = "$%#@!*-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";

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
            Assert.Throws<ArgumentException>(() => new JwtService(null));
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
                        notBefore: DateTime.Now.AddSeconds(1)
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
    }
}
