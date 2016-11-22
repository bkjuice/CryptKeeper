using System;
using System.Diagnostics.Contracts;

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

        public void Release(int index)
        {
            if (index < 0)
            {
                return;
            }

            this.cache[index].InUse = false;
        }

        private struct PooledInstance
        {
            public T Target;

            public bool InUse;
        }
    }
}
