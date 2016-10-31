using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretUseAsStringActionOfTTreatsEmptyAsEmpty()
        {
            var theSecret = string.Empty;
            AssertSecretActionOfTMatches("some state", theSecret);
            theSecret.Should().Be(string.Empty);
        }

        [TestMethod]
        public void SecretUseAsStringActionOfTRoundTripsStringDataAsExpected()
        {
            var theSecret = "don't tell anyone";
            AssertSecretActionOfTMatches("some state", theSecret);
        }

        [TestMethod]
        public void SecretUseAsStringActionOfNullifiesValueAfterUse()
        {
            using (var secret = new Secret("this will be all nulls"))
            {
                string data = null;
                secret.UseAsString("some state", (s1, s) => { data = s; });
                data.ToCharArray().Should().OnlyContain(c => c == '\0');
            }
        }

        [TestMethod]
        public void SecretUseAsStringActionOfTNullifiesValueRegardlessOfException()
        {
            var theSecret = "this is no news";
            string data = null;
            using (var secret = new Secret(theSecret))
            {
                try
                {
                    secret.UseAsString("some state", (s1, s) => { data = s; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.ToCharArray().Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTRoundTripsDataAsExpectedWithEvenByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            AssertSecretActionOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTRoundTripsDataAsExpectedWithOddByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3 };
            AssertSecretActionOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTMatchesEmptyArrayAsExpected()
        {
            var data = new byte[] { };
            AssertSecretActionOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTIncludesLastZeroAsPartOfValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretActionOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTIncludesFirstZeroAsPartOfValue()
        {
            var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretActionOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTDestroysValueAfterUse()
        {
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                byte[] data = null;
                secret.UseAsBytes("some state", (s, b) => { data = b; });
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretUseAsBytesActionOfTDestroysValueRegardlessOfException()
        {
            byte[] data = null;
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                try
                {
                    secret.UseAsBytes("some state", (s, b) => { data = b; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.Should().OnlyContain(b => b == 0);
        }

        private static void AssertSecretActionOfTMatches(string state, byte[] data)
        {
            var copy = new byte[data.Length];
            data.CopyTo(copy, 0);
            using (var secret = new Secret(data))
            {
                secret.UseAsBytes(state, (s, b) =>
                {
                    b.Should().ContainInOrder(copy);
                    ReferenceEquals(s, state).Should().BeTrue();
                });
            }
        }

        private static void AssertSecretActionOfTMatches(string state, string data)
        {
            var copy = new string(data.ToCharArray());
            using (var secret = new Secret(data))
            {
                secret.UseAsString(state, (s, b) =>
                {
                    b.Should().Be(copy);
                    ReferenceEquals(s, state).Should().BeTrue();
                });
            }
        }
    }
}
