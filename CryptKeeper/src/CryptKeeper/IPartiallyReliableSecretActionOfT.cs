using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IPartiallyReliableSecretAction<T>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        void Callback(T state, byte[] secret);
    }
}
