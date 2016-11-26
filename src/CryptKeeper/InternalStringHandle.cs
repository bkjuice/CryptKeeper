using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    internal unsafe class InternalStringHandle : SecretHandle
    {
        private readonly GCHandle Pin;

        public InternalStringHandle(int length) : base(length)
        {
            if (length < 1) return;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                this.Pin = GCHandle.Alloc(new string('\0', length), GCHandleType.Pinned);
            }
        }

        public char* P()
        {
            this.Use();
            return (char*)Pin.AddrOfPinnedObject();
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
     
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Nullify()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                if (this.length > 0 && Pin.IsAllocated)
                {
                    var c = (char*)Pin.AddrOfPinnedObject();
                    if (c != null)
                    {
                        for (int i = 0; i < length; i++)
                        {
                            c[i] = '\0';
                        }

                    }

                    Pin.Free();
                }
            }
        }
    }
}
