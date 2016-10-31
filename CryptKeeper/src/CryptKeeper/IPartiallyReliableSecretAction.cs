using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    public interface IPartiallyReliableSecretAction
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        void Callback(byte[] secret);
    }
}
