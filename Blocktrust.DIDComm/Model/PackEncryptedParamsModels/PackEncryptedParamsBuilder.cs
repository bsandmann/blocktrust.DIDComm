namespace Blocktrust.DIDComm.Model.PackEncryptedParamsModels;

using Blocktrust.Common.Resolver;
using Common.Algorithms;
using Exceptions;
using Message.Messages;
using Utils;

public class PackEncryptedParamsBuilder
{
    public Message Message { get; set; }
    public string To { get; set; }
    public string? from { get; set; }
    public string? signFrom { get; set; }
    public string? fromPriorIssuerKid { get; set; }
    public IDidDocResolver? didDocResolver { get; set; }
    public ISecretResolver? secretResolver { get; set; }
    public AuthCryptAlg encAlgAuth { get; set; } = new AuthCryptAlg(AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW); 
    public AnonCryptAlg encAlgAnon { get; set; } = new AnonCryptAlg(AnonCryptAlg.XC20P_ECDH_ES_A256KW);
    public bool protectSenderId { get; set; }
    public bool forward { get; set; } = true;
    public Dictionary<string, object>? forwardHeaders { get; set; }
    public string? forwardServiceId { get; set; }
    
    
    public PackEncryptedParamsBuilder(Message message, string to)
    {
        this.Message = message;
        this.To = to;
    }

    public PackEncryptedParamsBuilder SignFrom(string signFrom)
    {
        this.signFrom = signFrom;
        return this;
    }

    public PackEncryptedParamsBuilder FromPriorIssuerKid(string fromPriorIssuerKid)
    {
        this.fromPriorIssuerKid = fromPriorIssuerKid;
        return this;
    }

    public PackEncryptedParamsBuilder DidDocResolver(IDidDocResolver ididDocResolver)
    {
        this.didDocResolver = ididDocResolver;
        return this;
    }

    public PackEncryptedParamsBuilder SecretResolver(ISecretResolver secretResolver)
    {
        this.secretResolver = secretResolver;
        return this;
    }

    public PackEncryptedParamsBuilder From(string from)
    {
        this.from = from;
        return this;
    }

    public PackEncryptedParamsBuilder EncAlgAuth(AuthCryptAlg encAlgAuth)
    {
        this.encAlgAuth = encAlgAuth;
        return this;
    }

    public PackEncryptedParamsBuilder EncAlgAnon(AnonCryptAlg encAlgAnon)
    {
        this.encAlgAnon = encAlgAnon;
        return this;
    }

    public PackEncryptedParamsBuilder ProtectSenderId(bool protectSenderId)
    {
        this.protectSenderId = protectSenderId;
        return this;
    }

    public PackEncryptedParamsBuilder Forward(bool forward)
    {
        this.forward = forward;
        return this;
    }

    public PackEncryptedParamsBuilder ForwardHeaders(Dictionary<string, object> forwardHeaders)
    {
        this.forwardHeaders = forwardHeaders;
        return this;
    }

    public PackEncryptedParamsBuilder ForwardServiceId(string forwardServiceId)
    {
        this.forwardServiceId = forwardServiceId;
        return this;
    }
    
    public PackEncryptedParams BuildPackEncryptedParams()
    {
        string? from = this.from;
        string to = this.To;
        string? signFrom = this.signFrom;
        string? fromPriorIssuerKid = this.fromPriorIssuerKid;

        if (!DidUtils.IsDid(to))
            throw new DidCommIllegalArgumentException(to);

        if (from != null && !DidUtils.IsDid(from))
            throw new DidCommIllegalArgumentException(from);

        if (signFrom != null && !DidUtils.IsDid(signFrom))
            throw new DidCommIllegalArgumentException(signFrom);

        if (this.Message.To != null && !this.Message.To.Contains(DidUtils.DivideDidFragment(to).First()))
            throw new DidCommIllegalArgumentException(to);

        if (from != null && this.Message.From != null && this.Message.From != DidUtils.DivideDidFragment(from).First())
            throw new DidCommIllegalArgumentException(from);

        if (fromPriorIssuerKid != null && (!DidUtils.IsDid(fromPriorIssuerKid) || !DidUtils.IsDidFragment(fromPriorIssuerKid)))
            throw new DidCommIllegalArgumentException(fromPriorIssuerKid);

        if (Message.FromPrior != null)
        {
            if (Message.FromPrior.Sub == Message.FromPrior.Iss)
                throw new DidCommIllegalArgumentException(Message.FromPrior.Sub);

            if (Message.From != null && Message.FromPrior.Sub != Message.From)
                throw new DidCommIllegalArgumentException(Message.FromPrior.Sub);

            if (fromPriorIssuerKid != null &&
                DidUtils.DivideDidFragment(fromPriorIssuerKid).First() != Message.FromPrior.Iss
               )
                throw new DidCommIllegalArgumentException(fromPriorIssuerKid);
        }

        return new PackEncryptedParams(this);
    }
}