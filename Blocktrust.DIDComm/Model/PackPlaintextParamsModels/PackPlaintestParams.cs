namespace Blocktrust.DIDComm.Model.PackPlaintextParamsModels;

using Blocktrust.Common.Resolver;
using Message.Messages;

public class PackPlaintextParams
{
    public Message Message { get; set; }
    public string? FromPriorIssuerKid { get; set; } = null;
    public IDidDocResolver? DidDocResolver { get; set; } = null;
    public ISecretResolver? SecretResolver { get; set; } = null;

    public PackPlaintextParams(Message message, string? fromPriorIssuerKid = null, IDidDocResolver? didDocResolver = null, ISecretResolver? secretResolver = null)
    {
        this.Message = message;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
        this.DidDocResolver = didDocResolver;
        this.SecretResolver = secretResolver;
    }

    public static PackPlaintextParamsBuilder Builder(Message message) => new PackPlaintextParamsBuilder(message);

   
}
