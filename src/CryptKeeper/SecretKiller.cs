using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    /// <summary>
    /// Sponsor class for extensions used to clear sensitive data from memory.
    /// </summary>
    public static class SecretKiller
    {
        /// <summary>
        /// Nullifies the specified string value.
        /// </summary>
        /// <param name="value">The sensitive value to nullify.</param>
        /// <remarks>
        /// This method will mutate the CLR immutable string using constrained execution regions. 
        /// This will effectively destroy sensitive data on the heap, and any references to the 
        /// string will not be null, but rather see a null array of chars of the same length as 
        /// the original value. This remaining length information is unavoidable.
        /// Also of note is this method does not pin the string on creation, so copies left behind 
        /// by the garbage collector may still exist on the heap.
        /// </remarks>
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
                    RuntimeHelpers.PrepareConstrainedRegions();
                    try { }
                    finally
                    {
                        handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                    }

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

        /// <summary>
        /// Clears the provided array using a constrained execution region (CER).
        /// </summary>
        /// <param name="data">The data to be cleared to the array type defaults.</param>
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
