using System.Runtime.ConstrainedExecution;

namespace CryptKeeper.ReliabilityProofs.Lib
{
    public interface IReliableSecretAction
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        void Callback();
    }
}
