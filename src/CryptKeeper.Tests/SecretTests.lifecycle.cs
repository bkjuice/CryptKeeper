using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Security;

namespace CryptKeeper.Tests
{
    [TestClass]
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
        public void SecretCtorThrowsArgumentOutOfRangeExceptionWhenStringTooLong()
        {
            var data = new string('x', 1025);
            Action test = () => new Secret(data);
            test.ShouldThrow<ArgumentOutOfRangeException>();
        }

        [TestMethod]
        public void SecretCtorThrowsArgumentOutOfRangeExceptionWhenSecureStringTooLong()
        {
            var data = new SecureString();
            for(int i = 0; i < 1026; ++i)
            {
                data.AppendChar('x');
            }

            Action test = () => new Secret(data);
            test.ShouldThrow<ArgumentOutOfRangeException>();
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

        [TestMethod]
        public void SecretIndicatesObjectIsDisposedWhenDisposed()
        {
            var secret = new Secret(new byte[] { });
            secret.IsDisposed.Should().BeFalse();
            secret.Dispose();
            secret.IsDisposed.Should().BeTrue();
        }

        [TestMethod]
        public void SecretThrowsObjectDisposedExceptionWhenAlreadyDisposed()
        {
            var secret = new Secret(new byte[] { });
            secret.Dispose();
            Action test = () => secret.UseAsBytes(b => { });
            test.ShouldThrow<ObjectDisposedException>();
        }
    }
}
