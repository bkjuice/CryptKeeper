using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    public static class SecretKiller
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public unsafe static void Nullify(this string value)
        {
            GCHandle handle = default(GCHandle);
            IntPtr ptr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!string.IsNullOrEmpty(value))
                {
                    handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                    ptr = handle.AddrOfPinnedObject();
                }
            }
            finally
            {
                handle.Nullify(value?.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        internal unsafe static void Nullify(this GCHandle handle, int? length)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                if (handle.IsAllocated)
                {
                    IntPtr ptr = handle.AddrOfPinnedObject();
                    if (ptr != IntPtr.Zero)
                    {
                        var stringGuts = (char*)ptr;
                        for (int index = 0; index < length; index++)
                        {
                            stringGuts[index] = '\0';
                        }

                        handle.Free();
                    }
                }
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static void ConstrainedClear(this Array data)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                if (data != null)
                {
                    Array.Clear(data, 0, data.Length);
                }
            }
        }
    }
}
