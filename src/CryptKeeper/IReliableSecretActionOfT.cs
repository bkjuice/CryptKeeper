using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretAction<T>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        void Callback(T state, byte[] secret, bool secretIsValid);
    }
}
