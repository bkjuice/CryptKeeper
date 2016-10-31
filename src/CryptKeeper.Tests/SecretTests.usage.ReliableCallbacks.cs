using CryptKeeper.Tests.SupportingTypes;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptKeeper.Tests
{
    public partial class SecretTests
    {
        [TestMethod]
        public void SecretUseAsBytesReliableCallbackActionIsInvoked()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsBytes(stub as IReliableSecretAction);
                stub.Invoked.Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseAsBytesReliableCallbackActionIsInvokedWithProvidedState()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsBytes("thestate", stub as IReliableSecretAction<string>);
                stub.Invoked.Should().BeTrue();
                stub.State.Should().Be("thestate");
            }
        }

        [TestMethod]
        public void SecretUseAsBytesReliableCallbackFuncIsInvoked()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsBytes(stub as IReliableSecretFunc<string>);
                stub.Invoked.Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseAsBytesReliableCallbackFuncIsInvokedWithProvidedState()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsBytes("thestate", stub as IReliableSecretFunc<string, string>);
                stub.Invoked.Should().BeTrue();
                stub.State.Should().Be("thestate");
            }
        }

        [TestMethod]
        public void SecretUseAsStringReliableCallbackActionIsInvoked()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsString(stub as IReliableSecretStringAction);
                stub.Invoked.Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseAsStringReliableCallbackActionIsInvokedWithProvidedState()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsString("thestate", stub as IReliableSecretStringAction<string>);
                stub.Invoked.Should().BeTrue();
                stub.State.Should().Be("thestate");
            }
        }

        [TestMethod]
        public void SecretUseAsStringReliableCallbackFuncIsInvoked()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsString(stub as IReliableSecretStringFunc<string>);
                stub.Invoked.Should().BeTrue();
            }
        }

        [TestMethod]
        public void SecretUseAsStringReliableCallbackFuncIsInvokedWithProvidedState()
        {
            var stub = new ReliableCallbackStub();
            using (var s = new Secret(new byte[] { 1, 2, 3, 4, 5 }))
            {
                s.UseAsString("thestate", stub as IReliableSecretStringFunc<string, string>);
                stub.Invoked.Should().BeTrue();
                stub.State.Should().Be("thestate");
            }
        }
    }
}