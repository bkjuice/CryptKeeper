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
        private static readonly InternalStringHandle EmptyHandle = new InternalStringHandle(0);

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
            catch
            {
                value.Nullify();
                throw;
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
            catch
            {
                value.ConstrainedClear();
                throw;
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
            catch
            {
                value.ConstrainedClear();
                throw;
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
            catch
            {
                value.ConstrainedClear();
                throw;
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
            catch
            {
                value.ConstrainedClear();
                throw;
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

            InternalStringHandle handle = default(InternalStringHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectString();
                callback(handle.Value);
            }
            catch
            {
                handle.Nullify();
                throw;
            }
            finally
            {
                handle.Nullify();
            }
        }

        public void UseAsString<T>(T state, Action<T, string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            InternalStringHandle handle = default(InternalStringHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectString();
                callback(state, handle.Value);
            }
            catch
            {
                handle.Nullify();
                throw;
            }
            finally
            {
                handle.Nullify();
            }
        }

        public TResult UseAsString<TResult>(Func<string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            InternalStringHandle handle = default(InternalStringHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectString();
                return callback(handle.Value);
            }
            catch
            {
                handle.Nullify();
                throw;
            }
            finally
            {
                handle.Nullify();
            }
        }

        public TResult UseAsString<T, TResult>(T state, Func<T, string, TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            InternalStringHandle handle = default(InternalStringHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectString();
                return callback(state, handle.Value);
            }
            catch
            {
                handle.Nullify();
                throw;
            }
            finally
            {
                handle.Nullify();
            }
        }

        private byte[] UnprotectBytes()
        {
            if (this.size == 0)
            {
                return new byte[0];
            }

            // TODO: GC can copy this array...must stackalloc (?) or pin (probably in this case).
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

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        private unsafe InternalStringHandle UnprotectString()
        {
            if (this.size == 0)
            {
                return EmptyHandle;
            }

            var handle = new InternalStringHandle(this.size);
            IntPtr ptr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                RuntimeHelpers.PrepareConstrainedRegions();
                try { }
                finally
                {
                    ptr = Marshal.SecureStringToBSTR(this.secureValue);
                }

                for(int i = 0; i < this.size; ++i)
                {
                    handle.P[i] = ((char*)ptr)[i]; 
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(ptr);
                }
            }

            return handle;
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