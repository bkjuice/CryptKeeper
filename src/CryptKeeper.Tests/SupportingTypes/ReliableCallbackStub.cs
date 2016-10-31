using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptKeeper.Tests.SupportingTypes
{
    internal class ReliableCallbackStub : 
        IReliableSecretAction, 
        IReliableSecretAction<string>,
        IReliableSecretFunc<string>,
        IReliableSecretFunc<string, string>,
        IReliableSecretStringAction,
        IReliableSecretStringAction<string>,
        IReliableSecretStringFunc<string>,
        IReliableSecretStringFunc<string, string>
    {
        public bool Invoked { get; set; }

        public string State { get; set; }

        public void Callback(string secret)
        {
            this.Invoked = true;
        }

        public void Callback(byte[] secret)
        {
            this.Invoked = true;
        }

        public void Callback(string state, string secret)
        {
            this.Invoked = true;
            this.State = state;
        }

        public void Callback(string state, byte[] secret)
        {
            this.Invoked = true;
            this.State = state;
        }

        string IReliableSecretStringFunc<string>.Callback(string secret)
        {
            this.Invoked = true;
            return "Inconsequential Result";
        }

        string IReliableSecretFunc<string>.Callback(byte[] secret)
        {
            this.Invoked = true;
            return "Inconsequential Result";
        }

        string IReliableSecretStringFunc<string, string>.Callback(string state, string secret)
        {
            this.Invoked = true;
            this.State = state;
            return "Inconsequential Result";
        }

        string IReliableSecretFunc<string, string>.Callback(string state, byte[] secret)
        {
            this.Invoked = true;
            this.State = state;
            return "Inconsequential Result";
        }
    }
}
