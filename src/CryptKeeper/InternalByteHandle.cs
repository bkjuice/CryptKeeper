using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Threading;

namespace CryptKeeper
{
    internal unsafe class InternalByteHandle : SecretHandle
    {
        private static readonly byte[] Empty = new byte[0];

        private readonly GCHandle Pin;

        public InternalByteHandle(int length) : base(length)
        {
            if (length < 1) return;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                this.Pin = GCHandle.Alloc(new byte[length], GCHandleType.Pinned);
            }
        }

        public byte* P()
        {
            this.Use();
            return (byte*)Pin.AddrOfPinnedObject();
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
        public void NullifyAndFree()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                this.Nullify();
                Thread.MemoryBarrier();
                this.Free();
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
