using System;
using CryptKeeper.ReliabilityProofs.Lib;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretIsDestroyedOnOutOfMemoryExceptionForUseAsBytesFuncOfT()
        {
            var clearValue = default(byte[]);
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsBytes("some state", (x, b) =>
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
        public void SecretIsDestroyedWhenThreadIsAbortedForUseAsBytesFuncOfT()
        {
            var clearValue = default(byte[]);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsBytes("some state", (x, b) =>
                    {
                        clearValue = b;
                        testCer();
                        return "";
                    });
                };

                test.AbortTheThread();
            }
        }

        [TestMethod]
        public void SecretIsNullifiedOnOutOfMemoryExceptionForUseAsStringFuncOfT()
        {
            var clearValue = default(string);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsString("some state", (x, c) =>
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
        public void SecretIsNullifiedWhenThreadIsAbortedForUseAsStringFuncOfT()
        {
            var clearValue = default(string);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = testCer =>
                {
                    s.UseAsString("some state", (x, c) =>
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
