using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    [TestClass]
    public class SecretKillerTests
    {
        [TestMethod]
        public void SecretKillerNullifyNullsAllChars()
        {
            var input = "this is a string";
            input.Nullify();
            input.ToCharArray().Should().OnlyContain(c => c == '\0');
        }

        [TestMethod]
        public void SecretKillerNullifyDoesNotFailOnNullString()
        {
            string input = null;
            Action test = () => input.Nullify();
            test.ShouldNotThrow();
        }

        [TestMethod]
        public void SecretKillerConstrainedClearClearsArray()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6 };
            data.ConstrainedClear();
            data.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretKillerConstrainedClearDoesNotFailOnNullArray()
        {
            byte[] data = null;
            Action test = () => data.ConstrainedClear();
            test.ShouldNotThrow();
        }
    }
}
