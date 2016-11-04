using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;

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
            GCHandle handle = default(GCHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString(out handle);
                callback(value);
            }
            finally
            {
                handle.Nullify(value?.Length);
            }
        }

        public void UseAsString<T>(T state, Action<T, string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            GCHandle handle = default(GCHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString(out handle);
                callback(state, value);
            }
            finally
            {
                handle.Nullify(value?.Length);
            }
        }

        public TResult UseAsString<TResult>(Func<string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            GCHandle handle = default(GCHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString(out handle);
                return callback(value);
            }
            finally
            {
                handle.Nullify(value?.Length);
            }
        }

        public TResult UseAsString<T, TResult>(T state, Func<T, string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);

            this.ThrowIfDisposed();
            string value = null;
            GCHandle handle = default(GCHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                value = this.UnprotectString(out handle);
                return callback(state, value);
            }
            finally
            {
                handle.Nullify(value?.Length);
            }
        }

        private byte[] UnprotectBytes()
        {
            if (this.size == 0)
            {
                return new byte[0];
            }

            var bytes = new byte[this.size];
            IntPtr ptr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                ptr = Marshal.SecureStringToCoTaskMemUnicode(this.secureValue);
                Marshal.Copy(ptr, bytes, 0, this.size);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                }
            }

            return bytes;
        }

        private string UnprotectString(out GCHandle pinnedHandle)
        {
            if (this.size == 0)
            {
                pinnedHandle = default(GCHandle);
                return string.Empty;
            }

            var chars = new char[this.size];
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                IntPtr ptr = IntPtr.Zero;
                RuntimeHelpers.PrepareConstrainedRegions();
                try
                {
                    ptr = Marshal.SecureStringToCoTaskMemUnicode(this.secureValue);
                    Marshal.Copy(ptr, chars, 0, this.size);
                }
                finally
                {
                    if (ptr != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                    }
                }

                Thread.MemoryBarrier();
                pinnedHandle = GCHandle.Alloc(new string(chars), GCHandleType.Pinned);
                return pinnedHandle.Target as string;
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