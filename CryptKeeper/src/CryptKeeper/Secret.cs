using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
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

            this.size = value.Length;
            var chars = new char[checked((value.Length - 1) / 2) + 1];
            var i = 0;
            var c = 0;
            for (i = 0; i < value.Length - 1; i += 2)
            {
                chars[c] = (char)(value[i] << 8 + value[i + 1]);
                c++;
            }

            if (i < value.Length)
            {
                chars[c] = (char)(value[i] << 8);
            }

            try
            {
                unsafe
                {
                    fixed (char* p = chars)
                    {
                        this.secureValue = new SecureString(p, chars.Length);
                    }
                }

                this.secureValue.MakeReadOnly();
            }
            finally
            {
                Array.Clear(chars, 0, chars.Length);
                Array.Clear(value, 0, value.Length);
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
                throw new ObjectDisposedException("This Secret object instance is disposed and cannot be used.");
            }
        }
    }
}