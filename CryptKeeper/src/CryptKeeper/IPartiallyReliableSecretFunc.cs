using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IPartiallyReliableSecretFunc<TResult>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        TResult Callback(byte[] secret);
    }
}
