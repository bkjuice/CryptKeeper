using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IReliableSecretAction
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        void Callback(byte[] secret);
    }
}
