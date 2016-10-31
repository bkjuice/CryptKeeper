using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IPartiallyReliableSecretFunc<T, TResult>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        TResult Callback(T state, byte[] secret);
    }
}
