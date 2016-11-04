using System;
using CryptKeeper.ReliabilityProofs.Lib;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretIsDestroyedOnOutOfMemoryExceptionForUseAsBytesFunc()
        {
            var clearValue = default(byte[]);
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsBytes(b =>
                    {
                        clearValue = b;
                        testCer();
                        return "";
                    });
                };

                test.BreakTheStack();
            }
            
            clearValue.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretIsDestroyedWhenThreadIsAbortedForUseAsBytesFunc()
        {
            var clearValue = default(byte[]);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsBytes(b =>
                    {
                        clearValue = b;
                        testCer();
                        return "";
                    });
                };

                test.AbortTheThread();
            }

            clearValue.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretIsNullifiedOnOutOfMemoryExceptionForUseAsStringFunc()
        {
            var clearValue = default(string);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsString(c =>
                    {
                        clearValue = c;
                        testCer();
                        return "";
                    });
                };

                test.BreakTheStack();
            }

            clearValue.ToCharArray().Should().OnlyContain(c => c == '\0');
        }

        [TestMethod]
        public void SecretIsNullifiedWhenThreadIsAbortedForUseAsStringFunc()
        {
            var clearValue = default(string);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsString(c =>
                    {
                        clearValue = c;
                        testCer();
                        return "";
                    });
                };

                test.AbortTheThread();
            }

            clearValue.ToCharArray().Should().OnlyContain(c => c == '\0');
        }
    }
}
