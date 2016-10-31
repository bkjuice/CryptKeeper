using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    [TestClass]
    public partial class SecretTests
    {
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
        public void SecretUseAsBytesFuncReturnsFunctionValue()
        {
            using (var secret = new Secret(new byte[] { }))
            {
                secret.UseAsBytes(b => true).Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseAsBytesActionPassesStateArgument()
        {
            var state = new object();
            using (var secret = new Secret(new byte[] { }))
            {
                secret.UseAsBytes(state, (s, b) => { ReferenceEquals(s, state).Should().BeTrue(); });
            }
        }

        [TestMethod]
        public void SecretUseAsBytesFuncPassesStateArgument()
        {
            var state = new object();
            using (var secret = new Secret(new byte[] { }))
            {
                secret.UseAsBytes(state, (s, b) => ReferenceEquals(s, state)).Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseAsBytesDestroysValueRegardlessOfException()
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
        public void SecretUseAsBytesDestroysValueAfterUse()
        {
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                byte[] data = null;
                secret.UseAsBytes(b => { data = b; });
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretUseAsStringNullifiesTheValueAfterUse()
        {
            using (var secret = new Secret("this will be all nulls"))
            {
                string data = null;
                secret.UseAsString(s => { data = s; });
                data.ToCharArray().Should().OnlyContain(c => c == '\0');
            }
        }

        [TestMethod]
        public void SecretUseAsStringRoundTripsStringDataAsExpected()
        {
            var theSecret = "don't tell anyone";
            AssertSecretMatches(theSecret);
        }

        [TestMethod]
        public void SecretUseAsStringTreatsEmptyAsEmpty()
        {
            var theSecret = string.Empty;
            AssertSecretMatches(theSecret);
            theSecret.Should().Be(string.Empty);
        }

        [TestMethod]
        public void SecretUseAsBytesRoundTripsDataAsExpectedWithEvenByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            AssertSecretMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesRoundTripsDataAsExpectedWithOddByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3 };
            AssertSecretMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesIncludesLastZeroAsPartOfValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesIncludesFirstZeroAsPartOfValue()
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
