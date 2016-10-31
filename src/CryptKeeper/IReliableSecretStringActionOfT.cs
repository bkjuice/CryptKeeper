using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretStringAction<T>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        void Callback(T state, string secret, bool secretIsValid);
    }
}
