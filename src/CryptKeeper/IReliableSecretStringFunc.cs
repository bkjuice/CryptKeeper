using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretStringFunc<TResult>
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        TResult Callback(string secret, bool secretIsValid);
    }
}
