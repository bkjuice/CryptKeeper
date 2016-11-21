using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Threading;

namespace CryptKeeper
{
    internal unsafe class InternalStringHandle : SafeHandle
    {
        public readonly GCHandle Pin;

        public readonly char* P;

        private readonly int length;

        public InternalStringHandle(int length) : base(IntPtr.Zero, true)
        {
            if (length < 1) return;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                this.Pin = GCHandle.Alloc(new string('\0', length), GCHandleType.Pinned);
            }

            this.P = (char*)Pin.AddrOfPinnedObject();
            this.length = length;
        }

        public string Value
        {
            get
            {
                if (Pin.IsAllocated)
                {
                    return Pin.Target as string;
                }

                return string.Empty;
            }
        }

        public override bool IsInvalid
        {
            get
            {
                return !Pin.IsAllocated;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Nullify()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                GC.WaitForPendingFinalizers();
                Thread.MemoryBarrier();
                if (this.length > 0 && Pin.IsAllocated)
                {
                    var c = (char*)Pin.AddrOfPinnedObject();
                    if (c != null)
                    {
                        for (int i = 0; i < length; i++)
                        {
                            c[i] = '\0';
                        }

                        Pin.Free();
                    }
                }
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            this.Nullify();
            return true;
        }
    }
}
