namespace Blocktrust.DIDComm.Model.PackEncryptedResultModels;

public class PackEncryptedResult
{
    public string PackedMessage { get; set; }
    public List<string> ToKids { get; set; }
    public string? FromKid { get; set; } = null;
    public string? SignFromKid { get; set; } = null;
    public string? FromPriorIssuerKid { get; set; } = null;
    public ServiceMetadata? ServiceMetadata { get; set; } = null;
    
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