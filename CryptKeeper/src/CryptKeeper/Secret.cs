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
            var chars = new char[len];

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                Buffer.BlockCopy(value, 0, chars, 0, value.Length);
                unsafe { fixed (char* p = chars) this.secureValue = new SecureString(p, len); }
                this.secureValue.MakeReadOnly();
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
                Array.Clear(chars, 0, len);
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

            var bytes = new byte[this.size];
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(secureValue);
                Marshal.Copy(ptr, bytes, 0, this.size);
                Marshal.ZeroFreeCoTaskMemUnicode(ptr);
            }

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