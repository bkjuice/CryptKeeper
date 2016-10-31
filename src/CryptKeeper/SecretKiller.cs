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
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                if (!string.IsNullOrEmpty(value))
                {
                    var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                    if (handle.IsAllocated)
                    {
                        var innerChars = (char*)handle.AddrOfPinnedObject();
                        for (int index = 0; index < value.Length; index++)
                        {
                            innerChars[index] = '\0';
                        }

                        handle.Free();
                    }
                }
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static void ConstrainedClear(this byte[] data)
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
