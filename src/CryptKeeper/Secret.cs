using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;

namespace CryptKeeper
{
    /// <summary>
    /// Container class used to store and access values as a <see cref="SecureString"/> and reliably 
    /// destroy the clear text information after use.
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public sealed class Secret : IDisposable
    {
        private static readonly InternalStringHandle EmptyStringHandle = new InternalStringHandle(0);

        private static readonly InternalByteHandle EmptyBytesHandle = new InternalByteHandle(0);

        private readonly SecureString secureValue;

        private readonly int size;

        private bool disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class to protect binary data.
        /// </summary>
        /// <param name="value">The clear value to protect, which will be destroyed once protected.</param>
        /// <remarks>
        /// Be aware that if the provided value is not pinned on initialization, the garbage collector
        /// can leave behind copies of this value. Prefer to initialize the <see cref="Secret"/> instance
        /// with a <see cref="SecureString"/>.
        /// </remarks>
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
                catch
                {
                    chars.ConstrainedClear();
                    throw;
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

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class to protect string data.
        /// </summary>
        /// <param name="value">The clear value to protect, which will be destroyed once protected.</param>
        /// <remarks>
        /// Be aware that if the provided value is not pinned on initialization, the garbage collector
        /// can leave behind copies of this value. Prefer to initialize the <see cref="Secret"/> instance
        /// with a <see cref="SecureString"/>.
        /// </remarks>
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

        /// <summary>
        /// (Preferred) Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        /// <param name="value">The value as a <see cref="SecureString"/> instance.</param>
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

        /// <summary>
        /// Gets the underlying secure string instance.
        /// </summary>
        public SecureString SecureValue
        {
            get
            {
                this.ThrowIfDisposed();
                return this.secureValue;
            }
        }

        /// <summary>
        /// Gets a value indicating whether this instance is disposed.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is disposed; otherwise, <c>false</c>.
        /// </value>
        public bool IsDisposed
        {
            get
            {
                return this.disposed;
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (!this.disposed)
            {
                this.secureValue.Dispose();
                this.disposed = true;
            }

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED byte array and reliably destroys the secret after use.
        /// </summary>
        /// <param name="callback">The callback to invoke with the unprotected secret as a byte array.</param>
        public void UseAsBytes(Action<byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            var handle = default(InternalByteHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectBytes();
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED byte array and reliably destroys the secret after use. Use this overload to pass
        /// additional state to the callback and avoid closures for hot path code.
        /// </summary>
        /// <typeparam name="T">The type of state that will be passed to the provided callback.</typeparam>
        /// <param name="state">The state to be passed to the provided callback.</param>
        /// <param name="callback">The callback to invoke with the unprotected secret as a byte array.</param>
        public void UseAsBytes<T>(T state, Action<T, byte[]> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            var handle = default(InternalByteHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectBytes();
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED byte array and reliably destroys the secret after use.
        /// </summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="callback">The callback to invoke with the unprotected secret as a byte array.</param>
        /// <returns>The callback result.</returns>
        public TResult UseAsBytes<TResult>(Func<byte[], TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            var handle = default(InternalByteHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectBytes();
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED byte array and reliably destroys the secret after use. Use this overload to pass
        /// additional state to the callback and avoid closures for hot path code.
        /// </summary>
        /// <typeparam name="T">The type of state that will be passed to the provided callback.</typeparam>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="state">The state to be passed to the provided callback.</param>
        /// <param name="callback">The callback to invoke with the unprotected secret as a byte array.</param>
        /// <returns>
        /// The callback result.
        /// </returns>
        public TResult UseAsBytes<T, TResult>(T state, Func<T, byte[], TResult> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            var handle = default(InternalByteHandle);
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                handle = this.UnprotectBytes();
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED string and reliably destroys the secret after use.
        /// </summary>
        /// <param name="callback">The callback to invoke with the unprotected secret as a string.</param>
        public void UseAsString(Action<string> callback)
        {
            Contract.Requires<ArgumentNullException>(callback != null);
            this.ThrowIfDisposed();

            var handle = default(InternalStringHandle);
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED string and reliably destroys the secret after use. Use this overload to pass
        /// additional state to the callback and avoid closures for hot path code.
        /// </summary>
        /// <typeparam name="T">The type of state that will be passed to the provided callback.</typeparam>
        /// <param name="state">The state to be passed to the provided callback.</param>
        /// <param name="callback">The callback to invoke with the unprotected secret as a string.</param>
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED string and reliably destroys the secret after use.
        /// </summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="callback">The callback to invoke with the unprotected secret as a string.</param>
        /// <returns>
        /// The callback result.
        /// </returns>
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

        /// <summary>
        /// Allows for use of the protected secret as a GC PINNED string and reliably destroys the secret after use. Use this overload to pass
        /// additional state to the callback and avoid closures for hot path code.
        /// </summary>
        /// <typeparam name="T">The type of state that will be passed to the provided callback.</typeparam>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="state">The state to be passed to the provided callback.</param>
        /// <param name="callback">The callback to invoke with the unprotected secret as a string.</param>
        /// <returns>
        /// The callback result.
        /// </returns>
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

        private unsafe InternalByteHandle UnprotectBytes()
        {
            if (this.size == 0)
            {
                return EmptyBytesHandle;
            }

            var handle = new InternalByteHandle(this.size);
            IntPtr ptr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                RuntimeHelpers.PrepareConstrainedRegions();
                try { }
                finally
                {
                    ptr = Marshal.SecureStringToCoTaskMemUnicode(this.secureValue);
                }

                // TODO: Use a block copy mechanism that allows pointers...
                for (int i = 0; i < this.size; ++i)
                {
                    handle.P[i] = ((byte*)ptr)[i];
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                }
            }

            return handle;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        private unsafe InternalStringHandle UnprotectString()
        {
            if (this.size == 0)
            {
                return EmptyStringHandle;
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

                // TODO: Use a block copy mechanism that allows pointers...
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