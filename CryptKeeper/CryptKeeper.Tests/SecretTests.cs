using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

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
        public void SecretThrowsObjectDisposedExceptionWhenAlreadyDisposed()
        {
            var secret = new Secret(new byte[] { });
            secret.Dispose();
            Action test = () => secret.Use(b => { });
            test.ShouldThrow<ObjectDisposedException>();
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
                secret.Use(b => true).Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseActionPassesStateArgument()
        {
            var state = new object();
            using (var secret = new Secret(new byte[] { }))
            {
                secret.Use(state, (s, b) => { ReferenceEquals(s, state).Should().BeTrue(); });
            }
        }

        [TestMethod]
        public void SecretUseFuncPassesStateArgument()
        {
            var state = new object();
            using (var secret = new Secret(new byte[] { }))
            {
                secret.Use(state, (s, b) => ReferenceEquals(s, state)).Should().BeTrue();
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
                    secret.Use(b => { data = b; throw new InvalidOperationException(); });
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
                secret.Use(b => { data = b; });
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretThrowsArgumentNullExceptionWhenDataIsNull()
        {
            Action test = () => new Secret(null);
            test.ShouldThrow<ArgumentNullException>();
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
                secret.Use(b =>
                {
                    b.Should().ContainInOrder(copy);
                });
            }
        }
    }
}
