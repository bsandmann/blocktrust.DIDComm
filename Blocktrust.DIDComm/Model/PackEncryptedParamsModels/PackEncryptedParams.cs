namespace Blocktrust.DIDComm.Model.PackEncryptedParamsModels;

using Blocktrust.Common.Resolver;
using Common.Algorithms;
using Message.Messages;

public class PackEncryptedParams
{
    public Message Message { get; set; }
    public string To { get; set; }
    public string? From { get; set; }
    public string? SignFrom { get; set; }
    public string? FromPriorIssuerKid { get; set; }
    public AuthCryptAlg EncAlgAuth { get; set; }
    public AnonCryptAlg EncAlgAnon { get; set; }
    public bool ProtectSenderId { get; set; }
    public bool Forward { get; set; }
    public Dictionary<string, object>? ForwardHeaders { get; set; }
    public string ForwardServiceId { get; set; }
    public IDidDocResolver? DidDocResolver { get; set; }
    public ISecretResolver? SecretResolver { get; set; }

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