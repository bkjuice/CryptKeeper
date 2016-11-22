using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    internal class PinnedObjectPool<T> where T: class
    {
        private readonly PooledInstance[] cache;

        private Func<int, T> allocator;

        public PinnedObjectPool(int size, Func<int, T> allocator)
        {
            Contract.Requires(size > 0);

            this.cache = new PooledInstance[size];
            this.allocator = allocator;
        }

        public T Acquire()
        {
            lock (cache)
            {
                for (int i = 0; i < cache.Length; ++i)
                {
                    if (!cache[i].InUse)
                    {
                        if (cache[i].Target == null)
                        {
                            cache[i].Target = this.allocator(i);
                        }

                        cache[i].InUse = true;
                        return cache[i].Target;
                    }
                }
            }

            return allocator(-1);
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Release(int index)
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                if (index >= 0)
                {
                    lock (cache)
                    {
                        this.cache[index].InUse = false;
                    }
                }
            }
        }

        private struct PooledInstance
        {
            public T Target;

            public bool InUse;
        }
    }
}
