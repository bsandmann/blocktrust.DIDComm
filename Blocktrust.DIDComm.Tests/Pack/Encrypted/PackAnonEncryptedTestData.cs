namespace Blocktrust.DIDComm.Tests.Pack.Encrypted;

using Common.Algorithms;
using Message.Messages;

public class PackAnonEncryptedTestData
{
    public PackAnonEncryptedTestData(Message msg, AnonCryptAlg alg, string to, string signedFrom, bool protectSenderId)
    {
        this.Msg = msg;
        this.Alg = alg;
        this.To = to;
        this.SignedFrom = signedFrom;
        this.ProtectSenderId = protectSenderId;
    }
    
    public Message Msg { get; set; }
    public AnonCryptAlg Alg { get; set; }
    public string To { get; set; }
    public string SignedFrom { get; set; }
    public bool ProtectSenderId { get; set; }
}
