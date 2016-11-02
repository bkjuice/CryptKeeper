using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptKeeper.ReliabilityProofs.Lib
{
    public unsafe struct TooBigForTheStack
    {
        public fixed byte Bytes[int.MaxValue];
    }
}
