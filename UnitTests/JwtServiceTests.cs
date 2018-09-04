using System;
using System.Security;
using Xunit;

namespace GlitchedPolygons.Services.JwtService.UnitTests
{
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

        //[Fact]
        //public void GenerateToken_
        
    }
}
