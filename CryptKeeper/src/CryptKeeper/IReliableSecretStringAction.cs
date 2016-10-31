using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretStringAction
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        void Callback(string secret);
    }
}
