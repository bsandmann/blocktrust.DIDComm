namespace Blocktrust.DIDComm.Model.PackSignedParamsModels;

using Blocktrust.Common.Resolver;
using Message.Messages;

public class PackSignedParams
{
    /// <summary>
    /// The message to be packed into a Signed DIDComm message.
    /// </summary>
    public Message Message { get; }
    
    /// <summary>
    /// DID or key ID the sender uses for signing.
    /// </summary>
    public string SignFrom { get; }
    
    /// <summary>
    /// Sets Optional FromPrior issuer kid.
    /// </summary>
    public string? FromPriorIssuerKid { get; }
    
    /// <summary>
    /// Sets Optional DIDDoc resolver that can override a default DIDDoc resolver.
    /// </summary>
    public IDidDocResolver? DidDocResolver { get; }
    
    /// <summary>
    /// Sets Optional Secret resolver that can override a default Secret resolver.
    /// </summary>
    public ISecretResolver? SecretResolver { get; }

    public PackSignedParams(PackSignedParamsBuilder packSignedParamsBuilder)
    {
        Message = packSignedParamsBuilder.Message;
        SignFrom = packSignedParamsBuilder.SignFrom;
        FromPriorIssuerKid = packSignedParamsBuilder.fromPriorIssuerKid;
        DidDocResolver = packSignedParamsBuilder.IdidDocResolver;
        SecretResolver = packSignedParamsBuilder.secretResolver;
    }
}