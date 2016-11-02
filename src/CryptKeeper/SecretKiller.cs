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
                if (handle.IsAllocated && ptr != IntPtr.Zero)
                {
                    var stringGuts = (char*)ptr;
                    for (int index = 0; index < value.Length; index++)
                    {
                        stringGuts[index] = '\0';
                    }

                    handle.Free();
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
