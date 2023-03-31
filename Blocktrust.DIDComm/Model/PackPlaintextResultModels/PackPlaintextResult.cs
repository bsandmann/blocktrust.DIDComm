namespace Blocktrust.DIDComm.Model.PackPlaintextResultModels;

public class PackPlaintextResult
{
    public string PackedMessage { get; }
    public string? FromPriorIssuerKid { get; }

    public PackPlaintextResult(string packedMessage, string? fromPriorIssuerKid = null)
    {
        this.PackedMessage = packedMessage;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
    }
}
