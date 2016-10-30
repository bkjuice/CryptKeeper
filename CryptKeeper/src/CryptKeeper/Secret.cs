using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace CryptKeeper
{
    [SecuritySafeCritical]
    public sealed class Secret : IDisposable
    {
        private readonly SecureString secureValue;

        private readonly int size;

        private bool disposed;

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public Secret(byte[] value)
        {
            Contract.Requires<ArgumentNullException>(value != null);

            // Current max allowed RSA key is 16Kb:
            Contract.Requires<ArgumentOutOfRangeException>(value.Length < 2049, "The max supported secret size is 2KB (2048 bytes).");

            this.size = value.Length;
            var len = ((value.Length - 1) / 2) + 1;
            unsafe
            {
                try
                {
                    // A stack allocated char array is natural fit for the pointer based secure string ctor overload,
                    // and +offers deterministic destruction for this scope.
                    // However, this adds a small risk of an allocation fail if the current thread is in a deep call stack.
                    // Typical use of a Secret instance would be to keep a set of initialized secrets in memory for the 
                    // life of an app domain, in which case the ctor call will be in a very shallow call stack.
                    // Is this an attack vector? Only if a process is completely hijacked, and all bets are off at that point.
                    // By default, as of 10/2016, the default stack size is 1MB, and the max allocation will be 2KB:
                    var chars = stackalloc char[len]; 
                    var i = 0; var c = 0;
                    for (i = 0; i < value.Length - 1; i += 2)
                    {
                        chars[c] = (char)(value[i] << 8 + value[i + 1]);
                        c++;
                    }

                    if (i < value.Length) chars[c] = (char)(value[i] << 8);

                    this.secureValue = new SecureString(chars, len);
                    this.secureValue.MakeReadOnly();
                }
                finally
                {
                    Array.Clear(value, 0, value.Length);
                }
            }
        }

        public SecureString SecureValue
        {
            get
            {
                this.ThrowIfDisposed();
                return this.secureValue;
            }
        }

        public void Dispose()
        {
            if (!this.disposed)
            {
                this.secureValue.Dispose();
                this.disposed = true;
            }

            GC.SuppressFinalize(this);
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public void UseBytes(Action<byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                callback(value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public void UseBytes<T1>(T1 arg1, Action<T1, byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                callback(arg1, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TReturn UseBytes<TReturn>(Func<byte[], TReturn> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return callback(value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TReturn UseBytes<T1, TReturn>(T1 arg1, Func<T1, byte[], TReturn> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return callback(arg1, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        private byte[] UnprotectBytes(SecureString secureValue)
        {
            if (this.size == 0)
            {
                return new byte[0];
            }

            var len = secureValue.Length;
            var value = new char[len];

            var ptr = Marshal.SecureStringToCoTaskMemUnicode(secureValue);
            Marshal.Copy(ptr, value, 0, len);
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                Marshal.ZeroFreeCoTaskMemUnicode(ptr);
            }

            var bytes = new byte[this.size];
            var b = 0;

            const char byte1 = (char)(255 << 8);
            const char byte2 = (char)(0 << 8 + 255);
            for (int i = 0; i < value.Length; ++i)
            {
                bytes[b] = (byte)(value[i] & byte1);
                bytes[b++] = (byte)(value[i] & byte2);
            }

            if (b < this.size)
            {
                bytes[b] = (byte)(value[value.Length - 1] & byte1);
            }

            Array.Clear(value, 0, value.Length);
            return bytes;
        }

        private void ThrowIfDisposed()
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException("The secret instance is disposed and can no longer be used.");
            }
        }
    }
}