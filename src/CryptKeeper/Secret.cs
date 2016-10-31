using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace CryptKeeper
{
    public sealed class Secret : IDisposable
    {
        private readonly SecureString secureValue;

        private readonly int size;

        private bool disposed;

        public Secret(byte[] value)
        {
            Contract.Requires<ArgumentNullException>(value != null);
            Contract.Requires<ArgumentOutOfRangeException>(value.Length < 2049, "The max supported secret size is 2KB (2048 bytes).");

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
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
                    chars.ConstrainedClear();
                }
            }
            finally
            {
                value.ConstrainedClear();
            }
        }

        public Secret(string value)
        {
            Contract.Requires<ArgumentNullException>(value != null);

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                this.size = value.Length;
                unsafe { fixed (char* p = value) this.secureValue = new SecureString(p, value.Length); }
                this.secureValue.MakeReadOnly();
            }
            finally
            {
                value.Nullify();
            }
        }

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

        public SecureString SecureValue
        {
            get
            {
                this.ThrowIfDisposed();
                return this.secureValue;
            }
        }

        public bool IsDisposed
        {
            get
            {
                return this.disposed;
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

        public void UseAsBytes(Action<byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            byte[] value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectBytes();
                callback(value);
            }
            finally
            {
                value.ConstrainedClear();
            }
        }

        public void UseAsBytes<T>(T state, Action<T, byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            byte[] value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectBytes();
                callback(state, value);
            }
            finally
            {
                value.ConstrainedClear();
            }
        }

        public TResult UseAsBytes<TResult>(Func<byte[], TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            byte[] value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectBytes();
                return callback(value);
            }
            finally
            {
                value.ConstrainedClear();
            }
        }

        public TResult UseAsBytes<T, TResult>(T state, Func<T, byte[], TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            byte[] value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectBytes();
                return callback(state, value);
            }
            finally
            {
                value.ConstrainedClear();
            }
        }

        public void UseAsString(Action<string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString();
                callback(value);
            }
            finally
            {
                value.Nullify();
            }
        }

        public void UseAsString<T>(T state, Action<T, string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString();
                callback(state, value);
            }
            finally
            {
                value.Nullify();
            }
        }

        public TResult UseAsString<TResult>(Func<string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString();
                return callback(value);
            }
            finally
            {
                value.Nullify();
            }
        }

        public TResult UseAsString<T, TResult>(T state, Func<T, string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString();
                return callback(state, value);
            }
            finally
            {
                value.Nullify();
            }
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        private byte[] UnprotectBytes()
        {
            if (this.size == 0)
            {
                return new byte[0];
            }

            var bytes = new byte[this.size];
            RuntimeHelpers.PrepareConstrainedRegions();
            try { } finally
            {
                IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(this.secureValue);
                Marshal.Copy(ptr, bytes, 0, this.size);
                Marshal.ZeroFreeCoTaskMemUnicode(ptr);
            }

            return bytes;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        private string UnprotectString()
        {
            if (this.size == 0)
            {
                return string.Empty;
            }

            char[] chars = null;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                chars = new char[this.size];
                RuntimeHelpers.PrepareConstrainedRegions();
                try { } finally
                {
                    IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(this.secureValue);
                    Marshal.Copy(ptr, chars, 0, this.size);
                    Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                }

                return new string(chars);
            }
            finally
            {
                chars.ConstrainedClear();
            }
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