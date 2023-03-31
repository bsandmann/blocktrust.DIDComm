namespace Blocktrust.DIDComm.Model.PackEncryptedParamsModels;

using Blocktrust.Common.Resolver;
using Common.Algorithms;
using Message.Messages;

public class PackEncryptedParams
{
    /// <summary>
    /// The message to be packed into a Encrypted DIDComm message.
    /// </summary>
    public Message Message { get; }
    
    /// <summary>
    /// Identifiers (DID URLs) of recipient keys used for message encryption.
    /// </summary>
    public string To { get; }
    
    /// <summary>
    /// Identifier (DID URL) of sender key used for message encryption.
    /// null if anonymous (non-authenticated) encryption is used.
    /// </summary>
    public string? From { get; }
    
    /// <summary>
    /// Identifier (DID URL) of sender key used for message signing.
    /// </summary>
    public string? SignFrom { get; }
    
    /// <summary>
    ///  Optional FromPrior issuer kid.
    /// </summary>
    public string? FromPriorIssuerKid { get; }
    
    /// <summary>
    /// The encryption algorithm to be used for authentication encryption (auth_crypt).
    /// </summary>
    public AuthCryptAlg EncAlgAuth { get; }
    
    /// <summary>
    /// The encryption algorithm to be used for anonymous encryption (anon_crypt).
    /// </summary>
    public AnonCryptAlg EncAlgAnon { get; }
    
    /// <summary>
    /// Whether the sender's identity needs to be protected during authentication encryption.
    /// </summary>
    public bool ProtectSenderId { get; }
    
    /// <summary>
    /// Whether the packed messages need to be wrapped into Forward messages to be sent to Mediators
    /// defined by the Forward protocol. True by default.
    /// </summary>
    public bool Forward { get; }
    
    /// <summary>
    ///  If forward is enabled (true by default),
    ///  optional headers can be passed to the wrapping Forward messages.
    /// </summary>
    public Dictionary<string, object>? ForwardHeaders { get; }
    
    /// <summary>
    /// if forward is enabled (true by default),
    /// optional service ID from recipient's DID Doc to be used for Forwarding.
    /// </summary>
    public string ForwardServiceId { get; }
    
    /// <summary>
    /// Optional DIDDoc resolver that can override a default DIDDoc resolver.
    /// </summary>
    public IDidDocResolver? DidDocResolver { get; }
    
    /// <summary>
    /// Optional Secret resolver that can override a default Secret resolver.
    /// </summary>
    public ISecretResolver? SecretResolver { get; }

    public PackEncryptedParams(PackEncryptedParamsBuilder packEncryptedParamsBuilder)
    {
        Message = packEncryptedParamsBuilder.Message;
        To = packEncryptedParamsBuilder.To;
        From = packEncryptedParamsBuilder.from;
        SignFrom = packEncryptedParamsBuilder.signFrom;
        FromPriorIssuerKid = packEncryptedParamsBuilder.fromPriorIssuerKid;
        EncAlgAuth = packEncryptedParamsBuilder.encAlgAuth;
        EncAlgAnon = packEncryptedParamsBuilder.encAlgAnon;
        ProtectSenderId = packEncryptedParamsBuilder.protectSenderId;
        Forward = packEncryptedParamsBuilder.forward;
        ForwardHeaders = packEncryptedParamsBuilder.forwardHeaders;
        ForwardServiceId = packEncryptedParamsBuilder.forwardServiceId;
        DidDocResolver = packEncryptedParamsBuilder.didDocResolver;
        SecretResolver = packEncryptedParamsBuilder.secretResolver;
    }

    public static PackEncryptedParamsBuilder Builder(Message message, string to)
    {
        return new PackEncryptedParamsBuilder(message, to);
    }
    
   
}