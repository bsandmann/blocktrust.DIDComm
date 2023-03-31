namespace Blocktrust.DIDComm.Model.PackPlaintextParamsModels;

using Blocktrust.Common.Resolver;
using Message.Messages;

public class PackPlaintextParams
{
    /// <summary>
    /// The message to be packed into a Plaintext DIDComm message.
    /// </summary>
    public Message Message { get; }
    
    /// <summary>
    /// Optional FromPrior issuer kid.
    /// </summary>
    public string? FromPriorIssuerKid { get; }
    
    /// <summary>
    /// Optional DIDDoc resolver that can override a default DIDDoc resolver.
    /// </summary>
    public IDidDocResolver? DidDocResolver { get; }
    
    /// <summary>
    /// Optional Secret resolver that can override a default Secret resolver.
    /// </summary>
    public ISecretResolver? SecretResolver { get; }

    public PackPlaintextParams(Message message, string? fromPriorIssuerKid = null, IDidDocResolver? didDocResolver = null, ISecretResolver? secretResolver = null)
    {
        this.Message = message;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
        this.DidDocResolver = didDocResolver;
        this.SecretResolver = secretResolver;
    }

    public static PackPlaintextParamsBuilder Builder(Message message) => new PackPlaintextParamsBuilder(message);

   
}
