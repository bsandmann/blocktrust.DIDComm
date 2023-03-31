namespace Blocktrust.DIDComm.Model.PackEncryptedResultModels;

public class PackEncryptedResult
{
    public string PackedMessage { get; }
    public List<string> ToKids { get; }
    public string? FromKid { get; }
    public string? SignFromKid { get; }
    public string? FromPriorIssuerKid { get; }
    public ServiceMetadata? ServiceMetadata { get; }
    
    public PackEncryptedResult(string packedMessage, List<string> toKids, string? fromKid, string? signFromKid, string? fromPriorIssuerKid, ServiceMetadata? serviceMetadata)
    {
        this.PackedMessage = packedMessage;
        this.ToKids = toKids;
        this.FromKid = fromKid;
        this.SignFromKid = signFromKid;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
        this.ServiceMetadata = serviceMetadata;
    }
}