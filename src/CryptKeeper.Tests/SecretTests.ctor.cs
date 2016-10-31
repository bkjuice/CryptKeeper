using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Security;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretCtorHandlesEmptyArray()
        {
            Action test = () => new Secret(new byte[] { });
            test.ShouldNotThrow();
        }

        [TestMethod]
        public void SecretCtorInitializedWithSecureStringMakesSecureStringReadOnly()
        {
            using (var s = new SecureString())
            {
                using (var secret = new Secret(s))
                {
                    secret.SecureValue.IsReadOnly().Should().BeTrue();
                    ReferenceEquals(secret.SecureValue, s).Should().BeTrue();
                }
            }
        }

        [TestMethod]
        public void SecretCtorEnsuresSecureStringIsReadOnly()
        {
            using (var secret = new Secret(new byte[] { }))
            {
                secret.SecureValue.IsReadOnly().Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretCtorDestroysTheInputValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5 };
            using (var secret = new Secret(data)) { }
            data.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretCtorThrowsArgumentNullExceptionWhenDataIsNull()
        {
            Action test = () => new Secret(default(byte[]));
            test.ShouldThrow<ArgumentNullException>();
        }

        [TestMethod]
        public void SecretCtorNullifiesInputString()
        {
            var theSecret = "don't tell anyone";
            using (var s = new Secret(theSecret)) { }
            theSecret.ToCharArray().Should().OnlyContain(c => c == '\0');
        }
    }
}
