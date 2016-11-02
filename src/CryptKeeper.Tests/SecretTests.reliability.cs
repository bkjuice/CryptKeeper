using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Threading;
using CryptKeeper.ReliabilityProofs.Lib;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretIsDestroyedOnOutOfMemoryExceptionForUseAsBytesAction()
        {
            var clearValue = default(byte[]);
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }))
            {
                Action<Action> test = stackOverflow =>
                {
                    s.UseAsBytes(b =>
                    {
                        clearValue = b;
                        stackOverflow();
                    });
                };

                test.BreakTheStack();
            }
            
            clearValue.Should().OnlyContain(b => b == 0);
        }

        [TestMethod]
        public void SecretIsDestroyedWhenThreadIsAbortedForUseAsBytesAction()
        {
            var clearValue = default(byte[]);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = threadAbort =>
                {
                    s.UseAsBytes(b =>
                    {
                        clearValue = b;
                        threadAbort();
                    });
                };

                test.AbortTheThread();
            }
        }

        [TestMethod]
        public void SecretIsNullifiedOnOutOfMemoryExceptionForUseAsStringAction()
        {
            var clearValue = default(string);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = stackOverflow =>
                {
                    s.UseAsString(c =>
                    {
                        clearValue = c;
                        stackOverflow();
                    });
                };

                test.BreakTheStack();
            }

            clearValue.ToCharArray().Should().OnlyContain(c => c == '\0');
        }

        [TestMethod]
        public void SecretIsNullifiedWhenThreadIsAbortedForUseAsStringAction()
        {
            var clearValue = default(string);
            using (var s = new Secret("a string that shall never be spoken"))
            {
                Action<Action> test = threadAbort =>
                {
                    s.UseAsString(c =>
                    {
                        clearValue = c;
                        threadAbort();
                    });
                };

                test.AbortTheThread();
            }

            clearValue.ToCharArray().Should().OnlyContain(c => c == '\0');
        }
    }
}
