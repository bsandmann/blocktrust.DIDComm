namespace Blocktrust.DIDComm.Model.PackPlaintextResultModels;

public class PackPlaintextResult
{
    public string PackedMessage;
    public string FromPriorIssuerKid = null;

    public PackPlaintextResult(string packedMessage, string fromPriorIssuerKid = null)
    {
        this.PackedMessage = packedMessage;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
    }
}
