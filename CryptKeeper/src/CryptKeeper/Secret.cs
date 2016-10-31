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

        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.None)]
        public Secret(byte[] value)
        {
            Contract.Requires<ArgumentNullException>(value != null);
            Contract.Requires<ArgumentOutOfRangeException>(value.Length < 2049, "The max supported secret size is 2KB (2048 bytes).");

            this.size = value.Length;
            var len = ((value.Length - 1) / 2) + 1;
            var chars = new char[len];

            try
            {
                Buffer.BlockCopy(value, 0, chars, 0, value.Length);
                unsafe { fixed (char* p = chars) this.secureValue = new SecureString(p, len); }
                this.secureValue.MakeReadOnly();
            }
            finally
            {
                RuntimeHelpers.PrepareConstrainedRegions();
                try { } finally
                {
                    Array.Clear(value, 0, value.Length);
                    Array.Clear(chars, 0, len);
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
        public void Use(Action<byte[]> callback)
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

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        public void Use(IPartiallyReliableSecretAction handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                handler.Callback(value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Use(IReliableSecretAction handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                handler.Callback(value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public void Use<T>(T state, Action<T, byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                callback(state, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        public void Use<T>(T state, IPartiallyReliableSecretAction<T> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                handler.Callback(state, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Use<T>(T state, IReliableSecretAction<T> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                handler.Callback(state, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TResult Use<TResult>(Func<byte[], TResult> callback)
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

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        public TResult Use<TResult>(IPartiallyReliableSecretFunc<TResult> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return handler.Callback(value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public TResult Use<TResult>(IReliableSecretFunc<TResult> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return handler.Callback(value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TResult Use<T, TResult>(T state, Func<T, byte[], TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return callback(state, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        public TResult Use<T, TResult>(T state, IPartiallyReliableSecretFunc<T, TResult> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return handler.Callback(state, value);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public TResult Use<T, TResult>(T state, IReliableSecretFunc<T, TResult> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return handler.Callback(state, value);
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