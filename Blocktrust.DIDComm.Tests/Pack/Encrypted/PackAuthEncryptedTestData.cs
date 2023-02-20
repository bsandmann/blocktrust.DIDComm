namespace Blocktrust.DIDComm.Tests.Pack.Encrypted;

using Common.Algorithms;
using Message.Messages;

public class PackAuthEncryptedTestData
{
    public PackAuthEncryptedTestData(Message msg, AuthCryptAlg authAlg, AnonCryptAlg anonAlg, TestUtils.KeyAgreementCurveType curveType, bool protectSenderId, string signedFrom)
    {
        Msg = msg;
        AuthAlg = authAlg;
        AnonAlg = anonAlg;
        CurveType = curveType;
        ProtectSenderId = protectSenderId;
        SignedFrom = signedFrom;
    }

    public Message Msg { get; set; }
    public AuthCryptAlg AuthAlg { get; set; }
    public AnonCryptAlg AnonAlg { get; set; }
    public TestUtils.KeyAgreementCurveType CurveType { get; set; }
    public bool ProtectSenderId { get; set; }
    public string SignedFrom { get; set; }
}