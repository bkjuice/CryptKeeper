using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Threading;

namespace CryptKeeper
{
    internal unsafe class PinnedStringHandle : SecretHandle
    {
        public PinnedStringHandle(int length) : base(length)
        {
            if (length < 1) return;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                this.Init(GCHandle.Alloc(new string('\0', length), GCHandleType.Pinned));
            }
        }

        public char* P()
        {
            return (char*)this.Use();
        }

        public string Value
        {
            get
            {
                return this.Target as string ?? string.Empty;
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
                this.Release();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Nullify()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                if (this.length > 0)
                {
                    var c = (char*)this.Ptr;
                    if (c != null)
                    {
                        for (int i = 0; i < length; i++)
                        {
                            c[i] = '\0';
                        }

                    }

                    this.UnpinIfNotCached();
                }
            }
        }
    }
}
