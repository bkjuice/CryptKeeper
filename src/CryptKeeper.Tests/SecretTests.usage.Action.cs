using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretUseAsStringActionTreatsEmptyAsEmpty()
        {
            var theSecret = string.Empty;
            AssertSecretActionMatches(theSecret);
            theSecret.Should().Be(string.Empty);
        }

        [TestMethod]
        public void SecretUseAsStringActionRoundTripsStringDataAsExpected()
        {
            var theSecret = "don't tell anyone";
            AssertSecretActionMatches(theSecret);
        }

        [TestMethod]
        public void SecretUseAsStringActionNullifiesValueAfterUse()
        {
            using (var secret = new Secret("this will be all nulls"))
            {
                string data = null;
                secret.UseAsString(s => { data = s; });
                data.ToCharArray().Should().OnlyContain(c => c == '\0');
            }
        }

        [TestMethod]
        public void SecretUseAsStringActionNullifiesValueRegardlessOfException()
        {
            var theSecret = "this is no news";
            string data = null;
            using (var secret = new Secret(theSecret))
            {
                try
                {
                    secret.UseAsString(s => { data = s; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.ToCharArray().Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretUseAsBytesActionRoundTripsDataAsExpectedWithEvenByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            AssertSecretActionMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionRoundTripsDataAsExpectedWithOddByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3 };
            AssertSecretActionMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionMatchesEmptyArrayAsExpected()
        {
            var data = new byte[] { };
            AssertSecretActionMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionIncludesLastZeroAsPartOfValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretActionMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionIncludesFirstZeroAsPartOfValue()
        {
            var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretActionMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesActionDestroysValueAfterUse()
        {
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                byte[] data = null;
                secret.UseAsBytes(b => { data = b; });
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretUseAsBytesActionDestroysValueRegardlessOfException()
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

        private static void AssertSecretActionMatches(byte[] data)
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

        private static void AssertSecretActionMatches(string data)
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
