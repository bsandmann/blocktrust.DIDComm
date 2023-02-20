﻿namespace Blocktrust.DIDComm;

using Blocktrust.Common.Resolver;
using Crypto.JWS;
using Crypto.Keys;
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

    public PackPlaintextResult PackPlaintext(PackPlaintextParams param)
    {
        var didDocResolver = param.DidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);

        return new PackPlaintextResult(message.ToString(), fromPriorIssuerKid);
    }

    public PackSignedResult PackSigned(PackSignedParams param)
    {
        var didDocResolver = param.IdidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);
        var signFromKey = senderKeySelector.FindSigningKey(param.SignFrom);
        var msg = Jws.Sign(message.ToString(), signFromKey);

        return new PackSignedResult(msg, signFromKey.Id, fromPriorIssuerKid);
    }


    public PackEncryptedResult PackEncrypted(PackEncryptedParams param)
    {
        var didDocResolver = param.DidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);
        var (payload, signFromKid) = Operations.PackEncrypt.SignIfNeeded(message.ToString(), param, senderKeySelector);
        var (encryptedResult, recipientKeys) = PackEncrypt.Encrypt(param, payload, senderKeySelector);
        var encryptResult = PackEncrypt.ProtectSenderIfNeeded(param, encryptedResult, recipientKeys);

        // TODO make that (along with service metadata) as
        //      an internal part of routing routine
        var didServicesChain = Routing.ResolveDidCommServicesChain(
            didDocResolver, param.To, param.ForwardServiceId
        );

        var wrapInForwardResult = PackEncrypt.WrapInForwardIfNeeded(
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

        return new PackEncryptedResult(
            encryptResult.PackedMessage,
            encryptedResult.ToKids,
            encryptedResult.FromKid,
            signFromKid,
            fromPriorIssuerKid,
            serviceMetadata
        );
    }

    public UnpackResult Unpack(UnpackParams param)
    {
        var didDocResolver = param.IdidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var recipientKeySelector = new RecipientKeySelector(didDocResolver, secretResolver);

        return Unpacker.Unpack(param, recipientKeySelector);
    }
}