using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Threading;

namespace CryptKeeper
{
    internal unsafe class PinnedByteHandle : SecretHandle
    {
        private static readonly byte[] Empty = new byte[0];

        public PinnedByteHandle(int length) : base(length)
        {
            if (length < 1) return;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                this.Init(GCHandle.Alloc(new byte[length], GCHandleType.Pinned));
            }
        }

        public byte* P()
        {
            return (byte*)this.Use();
        }

        public byte[] Value
        {
            get
            {
                return this.Target as byte[] ?? Empty;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void NullifyAndRelease()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                this.Nullify();
                Thread.MemoryBarrier();
                this.Release();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Nullify()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                if (this.length > 0)
                {
                    var p = (byte*)this.Ptr;
                    if (p != null)
                    {
                        for (int i = 0; i < length; i++)
                        {
                            p[i] = 0;
                        }

                    }

                    this.UnpinIfNotCached();
                }
            }
        }
    }
}
