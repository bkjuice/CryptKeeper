using System;
using CryptKeeper.ReliabilityProofs.Lib;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretIsDestroyedOnOutOfMemoryExceptionForUseAsBytesActionOfT()
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
                    });
                };

                test.BreakTheStack();
            }
            
            clearValue.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretIsDestroyedWhenThreadIsAbortedForUseAsBytesActionOfT()
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
                    });
                };

                test.AbortTheThread();
            }

            clearValue.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretIsNullifiedOnOutOfMemoryExceptionForUseAsStringActionOfT()
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
                    });
                };

                test.BreakTheStack();
            }

            clearValue.ToCharArray().Should().OnlyContain(c => c == '\0');
        }

        [TestMethod]
        public void SecretIsNullifiedWhenThreadIsAbortedForUseAsStringActionOfT()
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
                    });
                };

                test.AbortTheThread();
            }

            clearValue.ToCharArray().Should().OnlyContain(c => c == '\0');
        }
    }
}
