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

        private bool disposed;

        private int size;

        public Secret(byte[] value)
        {
            Contract.Requires<ArgumentNullException>(value != null);

            this.size = value.Length;
            var chars = new char[((value.Length - 1) / 2) + 1];
            int i = 0;
            for (i = 0; i < value.Length - 1; i += 2)
            {
                chars[i] = (char)(value[i] << 8 + value[i + 1]);
            }

            if (i < value.Length)
            {
                chars[i] = (char)(value[i] << 8);
            }

            try
            {
                unsafe
                {
                    fixed (char* p = chars)
                    {
                        var result = new SecureString(p, chars.Length);
                        result.MakeReadOnly();
                        this.secureValue = result;
                    }
                }
            }
            finally
            {
                Destroy(chars);
                Destroy(value);
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
                if (this.secureValue?.IsReadOnly() == false)
                {
                    this.secureValue?.Clear();
                }

                this.secureValue?.Dispose();
                this.disposed = true;
            }

            GC.SuppressFinalize(this);
        }

        public void UseBytes(Action<byte[]> callback)
        {
            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                callback(value);
            }
            finally
            {
                Destroy(value);
            }
        }

        public void UseBytes<T1>(T1 arg1, Action<T1, byte[]> callback)
        {
            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                callback(arg1, value);
            }
            finally
            {
                Destroy(value);
            }
        }

        public TReturn UseBytes<TReturn>(Func<byte[], TReturn> callback)
        {
            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return callback(value);
            }
            finally
            {
                Destroy(value);
            }
        }

        public TReturn UseBytes<T1, TReturn>(T1 arg1, Func<T1, byte[], TReturn> callback)
        {
            this.ThrowIfDisposed();
            var value = UnprotectBytes(this.secureValue);
            try
            {
                return callback(arg1, value);
            }
            finally
            {
                Destroy(value);
            }
        }

        private byte[] UnprotectBytes(SecureString secureValue)
        {
            if (secureValue.Length == 0)
            {
                return new byte[0];
            }

            var len = secureValue.Length;
            var value = new char[len];

            // CER here:
            var ptr = Marshal.SecureStringToCoTaskMemUnicode(secureValue);
            try
            {
                Marshal.Copy(ptr, value, 0, len);
                return GetBytesFromChars(value);
            }
            finally
            {
                Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                Destroy(value);
            }
        }

        private static char[] GetCharsFromBytes(byte[] bytes)
        {
            var chars = new char[((bytes.Length - 1) / 2) + 1];
            int i = 0;
            for (i = 0; i < bytes.Length - 1; i += 2)
            {
                chars[i] = (char)(bytes[i] << 8 + bytes[i + 1]);
            }

            if (i < bytes.Length)
            {
                chars[i] = (char)(bytes[i] << 8);
            }

            return chars;
        }

        private byte[] GetBytesFromChars(char[] chars)
        {
            var bytes = new byte[this.size];
            int b = 0;

            const char byte1 = (char)(255 << 8);
            const char byte2 = (char)(0 << 8 + 255);

            for (int i = 0; i < chars.Length; ++i)
            {
                bytes[b] = (byte)(chars[i] & byte1);
                bytes[b++] = (byte)(chars[i] & byte2);
            }

            if (b < this.size)
            {
                bytes[b] = (byte)(chars[chars.Length - 1] & byte1);
            }

            return bytes;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Destroy(Array secret)
        {
            Array.Clear(secret, 0, secret.Length);
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