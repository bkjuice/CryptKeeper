using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;
using System.Runtime.InteropServices;

namespace CryptKeeper.Tests
{
    [TestClass]
    public class BCLVerificationTests
    {
        [TestMethod]
        public void PinnedHandleIsNotAllocatedOnceReleased()
        {
            // Behavior dependency for conditional finalizer:
            var pin = GCHandle.Alloc(new byte[10], GCHandleType.Pinned);
            pin.IsAllocated.Should().BeTrue();
            pin.Free();
            pin.IsAllocated.Should().BeFalse();
        }
    }
}
