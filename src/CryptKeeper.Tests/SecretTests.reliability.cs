using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretIsDestroyedOnOutOfMemoryExceptionForUseAsBytesAction()
        {
            // see proofs for pattern
        }

        [TestMethod]
        public void SecretIsDestroyedWhenThreadIsAbortedForUseAsBytesAction()
        {
            /* SPEC:
             * Thread A is parent (test thread), has wait handle (use manual reset events) for signal from thread B
             * Thread A starts thread B then waits
             * Thread B uses a secret, inside secret callback: 
             *      assigns the secret to an outer scope reference ("theValue")
             *      signals Thread A, then waits on its own wait handle 
             * Thread A is signaled and aborts thread B
             * Catch ThreadAbortException { }
             * Finally {signal thread B's wait handle to ensure no goofy re-ordering or deadlocking with CER}
             * Assert "theValue" is properly destroyed
             */
        }

        [TestMethod]
        public void SecretIsNullifiedOnOutOfMemoryExceptionForUseAsStringAction()
        {
            // variant for string secret usage
        }

        [TestMethod]
        public void SecretIsNullifiedWhenThreadIsAbortedForUseAsStringAction()
        {
            // variant for string secret usage
        }
    }
}
