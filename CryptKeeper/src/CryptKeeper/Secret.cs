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
                Array.Clear(value, 0, value.Length);
                Array.Clear(chars, 0, len);
            }
        }

        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.None)]
        public Secret(SecureString value)
        {
            Contract.Requires<ArgumentNullException>(value != null);

            this.size = value.Length;
            this.secureValue = value;
            if (!value.IsReadOnly())
            {
                value.MakeReadOnly();
            }
        }

        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.None)]
        public Secret(string value)
        {
            this.size = value.Length;
            try
            {
                unsafe { fixed (char* p = value) this.secureValue = new SecureString(p, value.Length); }
                this.secureValue.MakeReadOnly();
            }
            finally
            {
                value.Nullify();
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
        public void UseAsBytes(Action<byte[]> callback)
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
        public void UseAsBytes<T>(T state, Action<T, byte[]> callback)
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

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TResult UseAsBytes<TResult>(Func<byte[], TResult> callback)
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
        public TResult UseAsBytes<T, TResult>(T state, Func<T, byte[], TResult> callback)
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

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void UseAsBytes(IReliableSecretAction handler)
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
        public void UseAsBytes<T>(T state, IReliableSecretAction<T> handler)
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
        public TResult UseAsBytes<TResult>(IReliableSecretFunc<TResult> handler)
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
        public TResult UseAsBytes<T, TResult>(T state, IReliableSecretFunc<T, TResult> handler)
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
        public void UseAsString(IReliableSecretStringAction handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                handler.Callback(value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void UseAsString<T>(T state, IReliableSecretStringAction<T> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                handler.Callback(state, value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public TResult UseAsString<TResult>(IReliableSecretStringFunc<TResult> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                return handler.Callback(value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public TResult UseAsString<T, TResult>(T state, IReliableSecretStringFunc<T, TResult> handler)
        {
            Contract.Requires<ArgumentNullException>(handler != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                return handler.Callback(state, value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public void UseAsString(Action<string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                callback(value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public void UseAsString<T>(T state, Action<T, string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                callback(state, value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TResult UseAsString<TResult>(Func<string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                return callback(value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.MayCorruptAppDomain, Cer.None)]
        public TResult UseAsString<T, TResult>(T state, Func<T, string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            var value = UnprotectString(this.secureValue);
            try
            {
                return callback(state, value);
            }
            finally
            {
                value.Nullify();
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

        private string UnprotectString(SecureString secureValue)
        {
            if (this.size == 0)
            {
                return string.Empty;
            }

            var chars = new char[this.size];
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(secureValue);
                Marshal.Copy(ptr, chars, 0, this.size);
                Marshal.ZeroFreeCoTaskMemUnicode(ptr);
            }

            var clearValue = new string(chars);
            Array.Clear(chars, 0, chars.Length);
            return clearValue;
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