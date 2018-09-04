using System;
using System.Security;
using Xunit;

namespace GlitchedPolygons.Services.JwtService.UnitTests
{
    public class JwtServiceTests
    {
        [Fact]
        public void Ctor_NullOrEmptyKey_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new JwtService(null));
            Assert.Throws<ArgumentException>(() => new JwtService(new SecureString()));
        }


    }
}
