using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using CryptKeeper.ReliabilityProofs.Lib;

namespace CryptKeeper.ReliabilityProofs
{
    public class Program
    {
        private static bool cerWorked;

        private static SecretCallbackThatMustExecute inlineHandler = new SecretCallbackThatMustExecute();

        private static IReliableSecretAction abstractHandler = new ExternalSecretCallbackThatMustExecute();

        private static SecretFake fakeSecret = new SecretFake();

        public static void Main(string[] args)
        {
            Console.Write("Use reliable CER method inline: ");
            try
            {
                cerWorked = true;
                AttemptToUseReliableMethod();
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine(cerWorked);
            }

            Console.Write("Use reliable CER method via inline interface and concrete class: ");
            try
            {
                cerWorked = true;
                AttemptToUseInlineReliableCallback();
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine(cerWorked);
            }

            Console.Write("Use reliable CER method via abstract interface: ");
            try
            {
                cerWorked = true;
                AttemptToUseAbstractReliableCallbackAsInterface();
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine(cerWorked);
            }

            Console.Write("Use reliable CER method via abstract interface and fake secret: ");
            try
            {
                cerWorked = true;
                AttemptToUseSecretFake();
            }
            catch (OutOfMemoryException)
            {
                Console.WriteLine(cerWorked);
            }

            Console.ReadLine();
        }

        private static void AttemptToUseInlineReliableCallback()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                cerWorked = false;
            }
            finally
            {
                inlineHandler.Callback();
            }
        }

        private static void AttemptToUseAbstractReliableCallbackAsInterface()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                cerWorked = false;
            }
            finally
            {
                abstractHandler.Callback();
            }
        }

        private static void AttemptToUsereferencedReliableCallback()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                cerWorked = false;
            }
            finally
            {
                inlineHandler.Callback();
            }
        }

        private static void AttemptToUseSecretFake()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                cerWorked = false;
            }
            finally
            {
                fakeSecret.Use(abstractHandler);
            }
        }

        private static void AttemptToUseReliableMethod()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                cerWorked = false;
            }
            finally
            {
                BreakTheStack();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        private unsafe static void BreakTheStack()
        {
            TooBigForTheStack big;
            big.Bytes[int.MaxValue - 1] = 1;
        }

        private class SecretCallbackThatMustExecute : IInlineReliableSecretAction
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            public unsafe void Callback()
            {
                TooBigForTheStack big;
                big.Bytes[int.MaxValue - 1] = 1;
            }
        }

        private class ExternalSecretCallbackThatMustExecute : IReliableSecretAction
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            public unsafe void Callback()
            {
                TooBigForTheStack big;
                big.Bytes[int.MaxValue - 1] = 1;
            }
        }

        private class SecretFake
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            public void Use(IReliableSecretAction handler)
            {
                handler.Callback();
            }
        }

        public interface IInlineReliableSecretAction
        {
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            void Callback();
        }
    }
}
