namespace Blocktrust.DIDComm.Tests.Pack.Signed;

using Message.Messages;

public class PackSignedTestData
{
    public Message Msg { get; set; }
    public string SignedFrom { get; set; }

    public PackSignedTestData(Message msg, string signedFrom)
    {
        Msg = msg;
        SignedFrom = signedFrom;
    } 
}