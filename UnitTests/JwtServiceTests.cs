using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
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
            var result = jwt.Validate(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);
        }

        [Fact]
        public async Task GenerateToken_NotYetValid_ShouldFailToValidate()
        {
            var jwt = new JwtService(key, clockSkew: TimeSpan.Zero);
            var token = jwt.GenerateToken(
                lifetime: TimeSpan.FromMilliseconds(6000),
                notBefore: DateTime.UtcNow.AddMilliseconds(1500)
            );

            var result = jwt.Validate(token);

            Assert.False(result.Successful);
            Assert.Null(result.ValidatedToken);
            Assert.NotNull(result.ErrorMessage);

            await Task.Delay(2500);
            result = jwt.Validate(token);

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
            var result = jwt.Validate(token);

            Assert.True(result.Successful);
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
            var result = jwt.Validate(token);

            Assert.True(result.Successful);
            Assert.Null(result.ErrorMessage);
            Assert.NotNull(result.ValidatedToken);
        }
    }
}
