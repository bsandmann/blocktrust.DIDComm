namespace Blocktrust.DIDComm.Model.PackPlaintextParamsModels;

using Blocktrust.Common.Resolver;
using Exceptions;
using Message.Messages;
using Utils;

public class PackPlaintextParamsBuilder
{
    internal Message Message { get; set; }
    internal string? fromPriorIssuerKid { get; set; } = null;
    internal IDidDocResolver? didDocResolver { get; set; } = null;
    internal ISecretResolver? secretResolver { get; set; } = null;

    public PackPlaintextParamsBuilder(Message message)
    {
        this.Message = message;
    }

    public PackPlaintextParamsBuilder FromPriorIssuerKid(string fromPriorIssuerKid)
    {
        this.fromPriorIssuerKid = fromPriorIssuerKid;
        return this;
    }

    public PackPlaintextParamsBuilder DidDocResolver(IDidDocResolver ididDocResolver)
    {
        this.didDocResolver = ididDocResolver;
        return this;
    }

    public PackPlaintextParamsBuilder SecretResolver(ISecretResolver secretResolver)
    {
        this.secretResolver = secretResolver;
        return this;
    }

    public PackPlaintextParams BuildPackPlaintext()
    {
        string? fromPriorIssuerKid = this.fromPriorIssuerKid;

        if (fromPriorIssuerKid != null && (!DidUtils.IsDid(fromPriorIssuerKid) || !DidUtils.IsDidFragment(fromPriorIssuerKid)))
            throw new DidCommIllegalArgumentException(fromPriorIssuerKid);

        if (Message.FromPrior != null)
        {
            if (Message.FromPrior.Sub == Message.FromPrior.Iss)
                throw new DidCommIllegalArgumentException(Message.FromPrior.Sub);

            if (Message.From != null && Message.FromPrior.Sub != Message.From)
                throw new DidCommIllegalArgumentException(Message.FromPrior.Sub);

            if (fromPriorIssuerKid != null && DidUtils.DivideDidFragment(fromPriorIssuerKid).First() != Message.FromPrior.Iss)
                throw new DidCommIllegalArgumentException(fromPriorIssuerKid);
        }

        return new PackPlaintextParams(Message, fromPriorIssuerKid, this.didDocResolver, this.secretResolver);
    }
}