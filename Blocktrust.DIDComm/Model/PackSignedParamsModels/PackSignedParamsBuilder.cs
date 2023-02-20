namespace Blocktrust.DIDComm.Model.PackSignedParamsModels;

using Blocktrust.Common.Resolver;
using Exceptions;
using Message.Messages;
using Utils;

public class PackSignedParamsBuilder
{
    public PackSignedParamsBuilder(Message message, string signFrom)
    {
        this.Message = message;
        this.SignFrom = signFrom;
        this.fromPriorIssuerKid = null;
        this.IdidDocResolver = null;
        this.secretResolver = null;
    }
    
    internal string fromPriorIssuerKid { get; private set; }
    internal IDidDocResolver IdidDocResolver { get; private set; }
    internal ISecretResolver secretResolver { get; private set; }
    public Message Message;
    public string SignFrom;

    public PackSignedParamsBuilder FromPriorIssuerKid(string fromPriorIssuerKid)
    {
        this.fromPriorIssuerKid = fromPriorIssuerKid;
        return this;
    }

    public PackSignedParamsBuilder DidDocResolver(IDidDocResolver ididDocResolver)
    {
        this.IdidDocResolver = ididDocResolver;
        return this;
    }

    public PackSignedParamsBuilder SecretResolver(ISecretResolver secretResolver)
    {
        this.secretResolver = secretResolver;
        return this;
    }

    public PackSignedParams BuildPackSginedParams()
    {
        string didFrom = DidUtils.DivideDidFragment(this.SignFrom).First();
        
        string fromPriorIssuerKid = this.fromPriorIssuerKid;

        if (!DidUtils.IsDid(this.SignFrom))
            throw new DidCommIllegalArgumentException(didFrom);

        if (this.Message.From != didFrom)
            throw new DidCommIllegalArgumentException(didFrom);

        if (fromPriorIssuerKid != null && (!DidUtils.IsDid(fromPriorIssuerKid) || !DidUtils.IsDidFragment(fromPriorIssuerKid)))
            throw new DidCommIllegalArgumentException(fromPriorIssuerKid);

        if (Message.FromPrior != null)
        {
            if (Message.FromPrior.Sub == Message.FromPrior.Iss)
                throw new DidCommIllegalArgumentException(Message.FromPrior.Sub);

            if (Message.FromPrior.Sub != Message.From)
                throw new DidCommIllegalArgumentException(Message.FromPrior.Sub);

            if (fromPriorIssuerKid != null &&
                DidUtils.DivideDidFragment(fromPriorIssuerKid).First() != Message.FromPrior.Iss
               )
                throw new DidCommIllegalArgumentException(fromPriorIssuerKid);
        }

        return new PackSignedParams(this);
    }
}