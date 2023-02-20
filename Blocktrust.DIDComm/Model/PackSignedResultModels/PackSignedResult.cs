namespace Blocktrust.DIDComm.Model.PackSignedResultModels;

public class PackSignedResult
{
    public string PackedMessage;
    public string SignFromKid;
    public string FromPriorIssuerKid = null;

    public PackSignedResult(string packedMessage, string signFromKid, string fromPriorIssuerKid = null)
    {
        this.PackedMessage = packedMessage;
        this.SignFromKid = signFromKid;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
    }
}