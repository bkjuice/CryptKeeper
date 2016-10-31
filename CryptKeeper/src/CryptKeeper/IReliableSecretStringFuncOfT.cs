using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretStringFunc<T, TResult>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        TResult Callback(T state, string secret);
    }
}
