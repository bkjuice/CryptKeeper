using System;
using System.Collections.Concurrent;
using System.Threading;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    [TestClass]
    public class CacheAndReuseSecretTests
    {
        private static ConcurrentDictionary<int, Secret> bytesCache = new ConcurrentDictionary<int, Secret>();

        private static ConcurrentDictionary<int, Secret> stringsCache = new ConcurrentDictionary<int, Secret>();

        private static readonly byte[] TheSecret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

        [ClassInitialize]
        public static void Init(TestContext context)
        {
            for (var i = 0; i < 1000; ++i)
            {
                bytesCache.AddOrUpdate(i, new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }), (j, t) => t);

                var s = new string(new char[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' });
                stringsCache.AddOrUpdate(i, new Secret(s), (j, t) => t);
            }
        }

        [TestMethod]
        public void ReusedSecretsWorkWhenUsingBytesViaActionCallbackLambda()
        {
            for (int i = 0; i < 1000; ++i)
            {
                bytesCache[i].UseAsBytes(b => TheActionLambda(b, i));
            }
        }

        [TestMethod]
        public void ReusedSecretsWorkWhenUsingAsStringViaActionCallbackLambda()
        {
            for (int i = 0; i < 1000; ++i)
            {
                stringsCache[i].UseAsString(s => TheActionLambda(s, i));
            }
        }

        [TestMethod]
        public void MultiThreadedUseCanExceedPinnedObjectPool()
        {
            var secret = new Secret(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, 2);

            var reset1 = new ManualResetEvent(false);
            var thread1 = new Thread(() => secret.UseAsBytes(b =>
            {
                b.Should().ContainInOrder(TheSecret);
                Thread.Yield();
                Thread.Sleep(50);
                reset1.Set();
            }));

            var reset2 = new ManualResetEvent(false);
            var thread2 = new Thread(() => secret.UseAsBytes(b =>
            {
                b.Should().ContainInOrder(TheSecret);
                Thread.Yield();
                Thread.Sleep(50);
                reset2.Set();
            }));

            var reset3 = new ManualResetEvent(false);
            var thread3 = new Thread(() => secret.UseAsBytes(b =>
            {
                b.Should().ContainInOrder(TheSecret);
                Thread.Yield();
                Thread.Sleep(50);
                reset3.Set();
            }));

            var reset4 = new ManualResetEvent(false);
            var thread4 = new Thread(() => secret.UseAsBytes(b =>
            {
                b.Should().ContainInOrder(TheSecret);
                Thread.Yield();
                Thread.Sleep(50);
                reset4.Set();
            }));

            Action test = () =>
            {
                thread1.Start();
                thread2.Start();
                thread3.Start();
                thread4.Start();

                reset1.WaitOne();
                reset2.WaitOne();
                reset3.WaitOne();
                reset4.WaitOne();

                thread1.Abort();
                thread2.Abort();
                thread3.Abort();
                thread4.Abort();
            };

            test.ShouldNotThrow();
        }

        private static void TheActionLambda(byte[] clearText, int i)
        {
            clearText.Should().ContainInOrder(TheSecret, $"The index { i.ToString() } should still work.");
        }

        private static void TheActionLambda(string clearText, int i)
        {
            clearText.Should().Be("1234567890", $"The index { i.ToString() } should still work.");
        }
    }
}