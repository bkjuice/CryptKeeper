using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretFunc<TResult>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        TResult Callback(byte[] secret);
    }
}
