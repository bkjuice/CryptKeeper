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
        private static Secret bytesSecret = new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, 32);

        private static Secret stringSecret = new Secret(new string(new char[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' }), 20);

        private static readonly byte[] TheSecret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

        [TestMethod]
        public void MultiThreadedUseCanExceedPinnedObjectPoolForBytesSecret()
        {
            var allResets = new ManualResetEvent[50];
            var allThreads = new Thread[50];
            for (var i = 0; i < 50; ++i)
            {
                var reset1 = new ManualResetEvent(false);
                var thread1 = new Thread(() => bytesSecret.UseAsBytes(b =>
                {
                    b.Should().ContainInOrder(TheSecret);
                    Thread.Yield();
                    reset1.Set();
                }));

                allResets[i] = reset1;
                allThreads[i] = thread1;
            }

            Action test = () =>
            {
                for (var i = 0; i < 50; ++i)
                {
                    allThreads[i].Start();
                }

                for (var i = 0; i < 50; ++i)
                {
                    allResets[i].WaitOne();
                }

                for (var i = 0; i < 50; ++i)
                {
                    allThreads[i].Abort();
                }
            };

            test.ShouldNotThrow();
        }

        [TestMethod]
        public void MultiThreadedUseCanExceedPinnedObjectPoolFoStringSecret()
        {
            var allResets = new ManualResetEvent[50];
            var allThreads = new Thread[50];
            for (var i = 0; i < 50; ++i)
            {
                var reset1 = new ManualResetEvent(false);
                var thread1 = new Thread(() => stringSecret.UseAsString(b =>
                {
                    b.Should().Be("1234567890");
                    Thread.Yield();
                    reset1.Set();
                }));

                allResets[i] = reset1;
                allThreads[i] = thread1;
            }

            Action test = () =>
            {
                for (var i = 0; i < 50; ++i)
                {
                    allThreads[i].Start();
                }

                for (var i = 0; i < 50; ++i)
                {
                    allResets[i].WaitOne();
                }

                for (var i = 0; i < 50; ++i)
                {
                    allThreads[i].Abort();
                }
            };

            test.ShouldNotThrow();
        }
    }
}