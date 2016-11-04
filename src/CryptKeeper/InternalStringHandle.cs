using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    internal unsafe struct InternalStringHandle
    {
        public readonly GCHandle Pin;

        public readonly char* P;

        private readonly int length;

        public InternalStringHandle(int length) : this()
        {
            this.Pin = GCHandle.Alloc(new string('\0', length), GCHandleType.Pinned);
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

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Nullify()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                if (Pin.IsAllocated)
                {
                    for (int index = 0; index < length; index++)
                    {
                        P[index] = '\0';
                    }

                    Pin.Free();
                }
            }
        }
    }
}
