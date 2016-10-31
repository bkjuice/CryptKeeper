using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    [TestClass]
    public class StringKillerTests
    {
        [TestMethod]
        public void StringKillerNullifiesAllChars()
        {
            var input = "this is a string";
            input.Nullify();
            input.ToCharArray().Should().OnlyContain(c => c == '\0');
        }
    }
}
