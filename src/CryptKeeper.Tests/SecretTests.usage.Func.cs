using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretUseAsStringFuncTreatsEmptyAsEmpty()
        {
            var theSecret = string.Empty;
            AssertSecretFuncMatches(theSecret);
            theSecret.Should().Be(string.Empty);
        }

        [TestMethod]
        public void SecretUseAsStringFuncRoundTripsStringDataAsExpected()
        {
            var theSecret = "don't tell anyone";
            AssertSecretFuncMatches(theSecret);
        }

        [TestMethod]
        public void SecretUseAsStringFuncNullifiesValueAfterUse()
        {
            using (var secret = new Secret("this will be all nulls"))
            {
                string data = secret.UseAsString(s => s);
                data.ToCharArray().Should().OnlyContain(c => c == '\0');
            }
        }

        [TestMethod]
        public void SecretUseAsStringFuncNullifiesValueRegardlessOfException()
        {
            var theSecret = "this is no news";
            string data = null;
            using (var secret = new Secret(theSecret))
            {
                try
                {
                    secret.UseAsString<object>(s => { data = s; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.ToCharArray().Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncRoundTripsDataAsExpectedWithEvenByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            AssertSecretFuncMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncRoundTripsDataAsExpectedWithOddByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3 };
            AssertSecretFuncMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncMatchesEmptyArrayAsExpected()
        {
            var data = new byte[] { };
            AssertSecretFuncMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncIncludesLastZeroAsPartOfValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretFuncMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncIncludesFirstZeroAsPartOfValue()
        {
            var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretFuncMatches(data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncDestroysValueAfterUse()
        {
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                byte[] data = secret.UseAsBytes(b => b);
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretUseAsBytesFuncDestroysValueRegardlessOfException()
        {
            byte[] data = null;
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                try
                {
                    secret.UseAsBytes<object>(b => { data = b; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.Should().OnlyContain(b => b == 0);
        }

        private static void AssertSecretFuncMatches(byte[] data)
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
                    return new object();
                });
            }
        }

        private static void AssertSecretFuncMatches(string data)
        {
            var copy = new string(data.ToCharArray());
            using (var secret = new Secret(data))
            {
                secret.UseAsString(b =>
                {
                    b.Should().Be(copy);
                    return new object();
                });
            }
        }
    }
}
