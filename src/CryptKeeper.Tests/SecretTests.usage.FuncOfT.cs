using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretUseAsStringFuncOfTTreatsEmptyAsEmpty()
        {
            var theSecret = string.Empty;
            AssertSecretFuncOfTMatches("some state", theSecret);
            theSecret.Should().Be(string.Empty);
        }

        [TestMethod]
        public void SecretUseAsStringFuncOfTRoundTripsStringDataAsExpected()
        {
            var theSecret = "don't tell anyone";
            AssertSecretFuncOfTMatches("some state", theSecret);
        }

        [TestMethod]
        public void SecretUseAsStringFuncOfTNullifiesValueAfterUse()
        {
            using (var secret = new Secret("this will be all nulls"))
            {
                string data = secret.UseAsString("some state", (s1, s) => s);
                data.ToCharArray().Should().OnlyContain(c => c == '\0');
            }
        }

        [TestMethod]
        public void SecretUseAsStringFuncOfTNullifiesValueRegardlessOfException()
        {
            var theSecret = "this is no news";
            string data = null;
            using (var secret = new Secret(theSecret))
            {
                try
                {
                    secret.UseAsString<object>("some state", (s1, s) => { data = s; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.ToCharArray().Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOfTRoundTripsDataAsExpectedWithEvenByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
            AssertSecretFuncOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOfTRoundTripsDataAsExpectedWithOddByteCount()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3 };
            AssertSecretFuncOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOfTIncludesLastZeroAsPartOfValue()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretFuncOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOfTIncludesFirstZeroAsPartOfValue()
        {
            var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 0 };
            AssertSecretFuncOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOfTMatchesEmptyArrayAsExpected()
        {
            var data = new byte[] { };
            AssertSecretFuncOfTMatches("some state", data);
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOfTDestroysValueAfterUse()
        {
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                byte[] data = secret.UseAsBytes("some state", (s, b) => b);
                data.Should().OnlyContain(b => b == 0);
            }
        }

        [TestMethod]
        public void SecretUseAsBytesFuncOFTDestroysValueRegardlessOfException()
        {
            byte[] data = null;
            using (var secret = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                try
                {
                    secret.UseAsBytes<object>("some state", (s, b) => { data = b; throw new InvalidOperationException(); });
                }
                catch (InvalidOperationException) { }
            }

            data.Should().OnlyContain(b => b == 0);
        }

        private static void AssertSecretFuncOfTMatches(string state, byte[] data)
        {
            // The clearing of the source secret will happen after construction 
            // and for assertion purposes, a copy must be made. This is opposite of 
            // production intent and for testing purposes only, and such copies should be flagged
            // in code review:
            var copy = new byte[data.Length];
            data.CopyTo(copy, 0);
            using (var secret = new Secret(data))
            {
                secret.UseAsBytes(state, (s, b) =>
                {
                    b.Should().ContainInOrder(copy);
                    ReferenceEquals(s, state).Should().BeTrue();
                    return new object();
                });
            }
        }

        private static void AssertSecretFuncOfTMatches(string state, string data)
        {
            var copy = new string(data.ToCharArray());
            using (var secret = new Secret(data))
            {
                secret.UseAsString(state, (s, b) =>
                {
                    b.Should().Be(copy);
                    ReferenceEquals(s, state).Should().BeTrue();
                    return new object();
                });
            }
        }
    }
}
