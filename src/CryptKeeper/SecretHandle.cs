using System.Runtime.ConstrainedExecution;

namespace CryptKeeper
{
    internal abstract class SecretHandle 
    {
        protected readonly int length;

        protected SecretHandle(int length) 
        {
            this.length = length;
        }

        public bool IsFree { get; private set; }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public void Free()
        {
            try { }
            finally
            {
                this.IsFree = false;
            }
        }

        protected void Use()
        {
            this.IsFree = false;
        }
    }
}
