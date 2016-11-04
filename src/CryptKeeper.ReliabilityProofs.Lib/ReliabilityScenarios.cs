using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CryptKeeper.ReliabilityProofs.Lib
{
    public static class ReliabilityScenarios
    {
        public unsafe static void BreakTheStack()
        {
            TooBigForTheStack big = new TooBigForTheStack();
            big.Bytes[int.MaxValue - 1] = 1;
        }

        public static void BreakTheStack(this Action<Action> test)
        {
            var notifyThrown = new ManualResetEvent(false);
            var t = new Thread(() =>
            {
                try
                {
                    test(BreakTheStack);
                }
                catch (OutOfMemoryException)
                {
                    notifyThrown.Set();
                }
            });

            t.Start();
            notifyThrown.WaitOne();
        }

        public static void AbortTheThread(this Action<Action> test)
        {
            /* SPEC:
             * Thread A is parent (test thread), has wait handle (use manual reset events) for signal from thread B
             * Thread A starts thread B then waits
             * Thread B uses a secret, inside secret callback: 
             *      assigns the secret to an outer scope reference ("theValue")
             *      signals Thread A, then waits on its own wait handle 
             * Thread A is signaled and aborts thread B
             * Catch ThreadAbortException {signal thread B's wait handle to ensure no goofy re-ordering or deadlocking with CER}
             * Assert "theValue" is properly destroyed
             */

            var parentNotify = new ManualResetEvent(false);
            var parentContinue = new ManualResetEvent(false);
            var t = new Thread(() => 
            {
                test(() =>
                {
                    try
                    {
                        parentNotify.Set();
                        new ManualResetEvent(false).WaitOne();
                    }
                    // TODO: The commented out pattern below causes a race condition and an 
                    // intermittent test failure. This needs investigation...CER executes, but after
                    // assertion.
                    //catch (ThreadAbortException)
                    //{
                    //    parentContinue.Set();
                    //    throw;
                    //}
                    finally
                    {
                        parentContinue.Set();
                    }
                });
            });

            t.Start();
            parentNotify.WaitOne();
            t.Abort();
            parentContinue.WaitOne();
        }
    }
}
