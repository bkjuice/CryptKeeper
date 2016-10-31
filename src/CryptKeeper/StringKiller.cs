using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    public static class StringKiller
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public unsafe static void Nullify(this string value)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    var len = value.Length;
                    var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                    if (handle.IsAllocated)
                    {
                        var innerChars = (char*)handle.AddrOfPinnedObject();
                        for (int index = 0; index < len; index++)
                        {
                            innerChars[index] = '\0';
                        }

                        handle.Free();
                    }
                }
            }
        }
    }
}
