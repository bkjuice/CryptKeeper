using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Security;

namespace CryptKeeper.Tests
{
    [TestClass]
    public class SecretTests
    {
        [TestMethod]
        public void SecretHandlesEmptyArray()
        {
            Action test = () => new Secret(new byte[] { });
            test.ShouldNotThrow();
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

        [TestMethod]
        public void SecretInitializedWithSecureStringMakesSecureStringReadOnly()
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
        public void SecretSecureStringIsReadOnly()
        {
            using (var secret = new Secret(new byte[] { }))
            {
                secret.SecureValue.IsReadOnly().Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseFuncReturnsFunctionValue()
        {
            using (var secret = new Secret(new byte[] { }))
            {
                secret.UseAsBytes(b => true).Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseActionPassesStateArgument()
        {
            var state = new object();
            using (var secret = new Secret(new byte[] { }))
            {
                secret.UseAsBytes(state, (s, b) => { ReferenceEquals(s, state).Should().BeTrue(); });
            }
        }

        [TestMethod]
        public void SecretUseFuncPassesStateArgument()
        {
            var state = new object();
            using (var secret = new Secret(new byte[] { }))
            {
                secret.UseAsBytes(state, (s, b) => ReferenceEquals(s, state)).Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretDestroysDataRegardlessOfException()
        {
            byte[] data = null;
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                try
                {
                    secret.UseAsBytes(b => { data = b; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretDestroysTheValueAfterUse()
        {
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                byte[] data = null;
                secret.UseAsBytes(b => { data = b; });
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretDestroysTheInputValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5 };
            using (var secret = new Secret(data)){ }
            data.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretThrowsArgumentNullExceptionWhenDataIsNull()
        {
            Action test = () => new Secret(default(byte[]));
            test.ShouldThrow<ArgumentNullException>();
        }

        [TestMethod]
        public void SecretNullifiesInputString()
        {
            var theSecret = "don't tell anyone";
            using (var s = new Secret(theSecret)) { }
            theSecret.ToCharArray().Should().OnlyContain(c => c == '\0');
        }

        [TestMethod]
        public void SecretNullifiesTheValueAfterUse()
        {
            using (var secret = new Secret("this will be all nulls"))
            {
                string data = null;
                secret.UseAsString(s => { data = s; });
                data.ToCharArray().Should().OnlyContain(c => c == '\0');
            }
        }

        [TestMethod]
        public void SecretRoundTripsStringDataAsExpected()
        {
            var theSecret = "don't tell anyone";
            AssertSecretMatches(theSecret);
        }

        [TestMethod]
        public void SecretAsStringTreatsEmptyAsEmpty()
        {
            var theSecret = string.Empty;
            AssertSecretMatches(theSecret);
            theSecret.Should().Be(string.Empty);
        }

        [TestMethod]
        public void SecretRoundTripsDataAsExpectedWithEvenByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            AssertSecretMatches(data);
        }

        [TestMethod]
        public void SecretRoundTripsDataAsExpectedWithOddByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3 };
            AssertSecretMatches(data);
        }

        [TestMethod]
        public void SecretIncludesLastZeroAsPartOfValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretMatches(data);
        }

        [TestMethod]
        public void SecretIncludesFirstZeroAsPartOfValue()
        {
            var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretMatches(data);
        }

        private static void AssertSecretMatches(byte[] data)
        {
            // The clearing of the source secret will happen after construction 
            // and for assertion purposes, a copy must be made. This is opposite of 
            // production intent and for testing purposes only, and such copies should be flagged
            // in code review:
            var copy = new byte[data.Length];
            data.CopyTo(copy, 0);
            using (var secret = new Secret(data))
            {
                secret.UseAsBytes(b =>
                {
                    b.Should().ContainInOrder(copy);
                });
            }
        }

        private static void AssertSecretMatches(string data)
        {
            var copy = new string(data.ToCharArray());
            using (var secret = new Secret(data))
            {
                secret.UseAsString(b =>
                {
                    b.Should().Be(copy);
                });
            }
        }
    }
}
