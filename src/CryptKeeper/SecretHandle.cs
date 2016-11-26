using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace CryptKeeper
{
    internal abstract class SecretHandle 
    {
        protected readonly int length;

        private GCHandle pin;

        protected SecretHandle(int length) 
        {
            this.length = length;
        }

        public bool IsFree { get; private set; }

        public bool IsCached { get; set; }

        protected object Target
        {
            get
            {
                if (this.pin.IsAllocated)
                {
                    return this.pin.Target;
                }

                return null;
            }
        }

        protected IntPtr Ptr
        {
            get
            {
                return this.pin.IsAllocated ? this.pin.AddrOfPinnedObject() : IntPtr.Zero;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected void Init(GCHandle handle)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                this.pin = handle;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected void Release()
        {
            try { }
            finally
            {
                this.IsFree = true;
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected void UnpinIfNotCached()
        {
            try { }
            finally
            {
                if (!this.IsCached)
                {
                    if (this.pin.IsAllocated)
                    {
                        this.pin.Free();
                    }
                }
            }
        }

        protected IntPtr Use()
        {
            this.IsFree = false;
            return this.Ptr;
        }
    }
}
