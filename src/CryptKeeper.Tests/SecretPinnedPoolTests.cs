using System;
using System.Collections.Concurrent;
using System.Threading;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    [TestClass]
    public class SecretPinnedPoolTests
    {
        private static Secret bytesSecret = new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, 8);

        private static Secret stringSecret = new Secret(new string(new char[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' }), 8);

        private static readonly byte[] TheSecret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

        [TestMethod]
        public void MultiThreadedUseCanExceedPinnedObjectPoolForBytesSecret50()
        {
            RunNThreads(50, () => 
            {
                bytesSecret.UseAsBytes(b =>
                {
                    b.Should().ContainInOrder(TheSecret);
                });
            });
        }

        [TestMethod]
        public void MultiThreadedUseCanExceedPinnedObjectPoolForBytesSecret150()
        {
            RunNThreads(150, () =>
            {
                bytesSecret.UseAsBytes(b =>
                {
                    b.Should().ContainInOrder(TheSecret);
                });
            });
        }

        [TestMethod]
        public void MultiThreadedUseCanExceedPinnedObjectPoolFoStringSecret()
        {
            RunNThreads(50, () =>
            {
                stringSecret.UseAsString(b =>
                {
                    b.Should().Be("1234567890");
                });
            });
        }

        public void RunNThreads(int n, Action assertion)
        {
            var allResets = new ManualResetEvent[n];
            var allThreads = new Thread[n];
            for (var i = 0; i < n; ++i)
            {
                var reset1 = new ManualResetEvent(false);
                var thread1 = new Thread(() =>
                {
                    assertion();
                    Thread.Yield();
                    reset1.Set();
                });

                allResets[i] = reset1;
                allThreads[i] = thread1;
            }

            Action test = () =>
            {
                for (var i = 0; i < n; ++i)
                {
                    allThreads[i].Start();
                }

                for (var i = 0; i < n; ++i)
                {
                    allResets[i].WaitOne();
                }

                for (var i = 0; i < n; ++i)
                {
                    allThreads[i].Abort();
                }
            };

            test.ShouldNotThrow();
        }
    }
}