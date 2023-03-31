namespace Blocktrust.DIDComm.Model.PackSignedResultModels;

public class PackSignedResult
{
    public string PackedMessage { get; }
    public string SignFromKid { get; }
    public string? FromPriorIssuerKid { get; }

    public PackSignedResult(string packedMessage, string signFromKid, string? fromPriorIssuerKid = null)
    {
        this.PackedMessage = packedMessage;
        this.SignFromKid = signFromKid;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
    }
}