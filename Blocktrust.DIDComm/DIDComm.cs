namespace Blocktrust.DIDComm;

using Blocktrust.Common.Resolver;
using Crypto.JWS;
using Crypto.Keys;
using FluentResults;
using Model.PackEncryptedParamsModels;
using Model.PackEncryptedResultModels;
using Model.PackPlaintextParamsModels;
using Model.PackPlaintextResultModels;
using Model.PackSignedParamsModels;
using Model.PackSignedResultModels;
using Model.UnpackParamsModels;
using Model.UnpackResultModels;
using Operations;
using ProtocolsRouting.Routing;

public class DidComm
{
    private IDidDocResolver _didDocResolver;
    private ISecretResolver _secretResolver;

    public DidComm(IDidDocResolver didDocResolver, ISecretResolver secretResolver)
    {
        this._didDocResolver = didDocResolver;
        this._secretResolver = secretResolver;
    }

    public async Task<Result<PackPlaintextResult>> PackPlaintext(PackPlaintextParams param)
    {
        var didDocResolver = param.DidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = await FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);

        return Result.Ok(new PackPlaintextResult(message.ToString(), fromPriorIssuerKid));
    }

    public async Task<Result<PackSignedResult>> PackSigned(PackSignedParams param)
    {
        var didDocResolver = param.IdidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = await FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);
        var signFromKey = await senderKeySelector.FindSigningKey(param.SignFrom);
        var msg = Jws.Sign(message.ToString(), signFromKey);

        return Result.Ok(new PackSignedResult(msg, signFromKey.Id, fromPriorIssuerKid));
    }


    public async Task<Result<PackEncryptedResult>> PackEncrypted(PackEncryptedParams param)
    {
        var didDocResolver = param.DidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = await FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);
        var (payload, signFromKid) = await Operations.PackEncrypt.SignIfNeeded(message.ToString(), param, senderKeySelector);
        var (encryptedResult, recipientKeys) = await PackEncrypt.Encrypt(param, payload, senderKeySelector);
        var encryptResult = PackEncrypt.ProtectSenderIfNeeded(param, encryptedResult, recipientKeys);

        // TODO make that (along with service metadata) as
        //      an internal part of routing routine
        var didServicesChain =await Routing.ResolveDidCommServicesChain(
            didDocResolver, param.To, param.ForwardServiceId
        );

        var wrapInForwardResult =await PackEncrypt.WrapInForwardIfNeeded(
            encryptResult.PackedMessage, param, didServicesChain, didDocResolver, secretResolver
        );

        if (wrapInForwardResult != null)
            encryptResult.PackedMessage = wrapInForwardResult.MsgEncrypted.PackedMessage;

        var serviceMetadata = !didServicesChain.Any()
            ? null
            : new ServiceMetadata(
                didServicesChain.Last().Id,
                didServicesChain.First().ServiceEndpoint
            );

        return Result.Ok(new PackEncryptedResult(
            encryptResult.PackedMessage,
            encryptedResult.ToKids,
            encryptedResult.FromKid,
            signFromKid,
            fromPriorIssuerKid,
            serviceMetadata
        ));
    }

    public async Task<Result<UnpackResult>> Unpack(UnpackParams param)
    {
        var didDocResolver = param.IdidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var recipientKeySelector = new RecipientKeySelector(didDocResolver, secretResolver);

        return await Unpacker.Unpack(param, recipientKeySelector);
    }
}