namespace Blocktrust.DIDComm.Tests.TestData.DIDDoc;

using Blocktrust.Common.Models.DidDoc;

public class DIDDocEllie
{
    public static DidDoc DID_DOC_ELLIE = new DidDoc
    {
        Did = "did:example:ellie",
        Authentications = new List<string>
        {
        },
        KeyAgreements = new List<string>
        {
        },
        Services = new List<Service>
        {
        },
        VerificationMethods = new List<VerificationMethod>
        {
        },
    };
}