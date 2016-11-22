using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    internal unsafe class InternalByteHandle 
    {
        private static readonly byte[] Empty = new byte[0];

        public readonly GCHandle Pin;

        public readonly byte* P;

        public readonly int CacheIndex;

        private readonly int length;

        public InternalByteHandle(int length, int index) 
        {
            if (length < 1) return;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                this.Pin = GCHandle.Alloc(new byte[length], GCHandleType.Pinned);
            }

            this.P = (byte*)Pin.AddrOfPinnedObject();
            this.length = length;
            this.CacheIndex = index;
        }

        public byte[] Value
        {
            get
            {
                if (Pin.IsAllocated)
                {
                    return Pin.Target as byte[];
                }

                return Empty;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Nullify()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                if (this.length > 0 && Pin.IsAllocated)
                {
                    var p = (byte*)Pin.AddrOfPinnedObject();
                    if (p != null)
                    {
                        for (int i = 0; i < length; i++)
                        {
                            p[i] = 0;
                        }

                    }

                    Pin.Free();
                }
            }
        }
    }
}
