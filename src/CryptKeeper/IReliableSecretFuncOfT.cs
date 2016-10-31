using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretFunc<T, TResult>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        TResult Callback(T state, byte[] secret, bool secretIsValid);
    }
}
