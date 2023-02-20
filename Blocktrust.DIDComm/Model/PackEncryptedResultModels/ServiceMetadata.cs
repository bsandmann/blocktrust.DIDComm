namespace Blocktrust.DIDComm.Model.PackEncryptedResultModels;

public class ServiceMetadata
{
    public string Id { get; set; }
    public string ServiceEndpoint { get; set; }

    public ServiceMetadata(string id, string serviceEndpoint)
    {
        this.Id = id;
        this.ServiceEndpoint = serviceEndpoint;
    }
}