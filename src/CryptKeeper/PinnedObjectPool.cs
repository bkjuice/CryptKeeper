﻿using System;
using System.Diagnostics.Contracts;
using System.Threading;

namespace CryptKeeper
{
    internal class PinnedObjectPool<T> where T : SecretHandle
    {
        private readonly T[] cache;

        private Func<T> allocator;

        private int next;

        public PinnedObjectPool(int size, Func<T> allocator)
        {
            Contract.Requires(size > -1);
            Contract.Requires(allocator != null);

            this.cache = new T[size];
            this.allocator = allocator;
        }

        public T Acquire()
        {
            var limit = this.cache.Length;
            if (limit == 0)
            {
                return this.allocator();
            }
            
            var wait = new SpinWait();
            while (wait.Count < limit)
            {
                var mySlot = next;
                Thread.MemoryBarrier();
                var slotAfterNext = (mySlot + 1 < limit) ? mySlot + 1 : 0;
                if (Interlocked.CompareExchange(ref this.next, slotAfterNext, mySlot) == mySlot)
                {
                    var handle = this.cache[mySlot];
                    if (handle == null)
                    {
                        handle = this.allocator();
                        this.cache[mySlot] = handle;
                        handle.IsCached = true;
                        return handle;
                    }

                    if (handle.IsFree)
                    {
                        return handle;
                    }
                }

                wait.SpinOnce();
            }

            return this.allocator();
        }
    }
}
