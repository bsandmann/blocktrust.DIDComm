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
    private readonly IDidDocResolver _didDocResolver;
    private readonly ISecretResolver _secretResolver;

    public DidComm(IDidDocResolver didDocResolver, ISecretResolver secretResolver)
    {
        this._didDocResolver = didDocResolver;
        this._secretResolver = secretResolver;
    }


    /// <summary>
    ///  Produces [DIDComm Plaintext Messages](https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages).
    ///  A DIDComm message in its plaintext form that
    ///  - is not packaged into any protective envelope;
    ///  - lacks confidentiality and integrity guarantees;
    ///  - repudiable.
    ///
    /// They are therefore not normally transported across security boundaries.
    /// However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    /// and it is the format used in the DIDComm spec to give examples of headers and other internals.
    /// Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
    /// </summary>
    /// <param name="param"></param>
    /// <returns></returns>
    public async Task<Result<PackPlaintextResult>> PackPlaintext(PackPlaintextParams param)
    {
        var didDocResolver = param.DidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = await FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);

        return Result.Ok(new PackPlaintextResult(message.ToString(), fromPriorIssuerKid));
    }

    /// <summary>
    /// Produces (DIDComm Signed Message)[https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message].
    /// The method signs (non-repudiation added) the message keeping it unencrypted.
    /// Signed messages are only necessary when
    ///  - the origin of plaintext must be provable to third parties;
    ///  - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
    ///    is not known in advance (e.g., in a broadcast scenario).
    /// Adding a signature when one is not needed can degrade rather than enhance security because it
    /// relinquishes the sender’s ability to speak off the record.
    ///
    /// Signing is done as follows:
    /// - Signing is done via the keys from the [authentications] verification relationship in the DID Doc
    ///   for the DID to be used for signing.
    /// - If [PackSignedParams.signFrom] is a DID, then the first sender's [authentications]
    ///   verification method is used for which a private key in the secrets resolver is found
    /// - If [PackSignedParams.signFrom]  is a key ID, then the sender's [authentications]
    ///  verification method identified by the given key ID is used.
    /// </summary>
    /// <param name="param"></param>
    /// <returns></returns>
    public async Task<Result<PackSignedResult>> PackSigned(PackSignedParams param)
    {
        var didDocResolver = param.DidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var senderKeySelector = new SenderKeySelector(didDocResolver, secretResolver);

        var (message, fromPriorIssuerKid) = await FromPrior.PackFromPrior(param.Message, param.FromPriorIssuerKid, senderKeySelector);
        var signFromKey = await senderKeySelector.FindSigningKey(param.SignFrom);
        var msg = Jws.Sign(message.ToString(), signFromKey);

        return Result.Ok(new PackSignedResult(msg, signFromKey.Id, fromPriorIssuerKid));
    }

    /// <summary>
    /// Produces [DIDComm Encrypted Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message).
    /// The method encrypts and optionally authenticates the message to the given recipient.
    ///
    /// A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that
    ///  - hides its content from all but authorized recipients;
    ///  - (optionally) discloses and proves the sender to only those recipients;
    ///  - provides message integrity guarantees.
    ///
    /// It is important in privacy-preserving routing.
    ///
    /// It is what normally moves over network transports in DIDComm
    /// applications, and is the safest format for storing DIDComm data at rest.
    ///
    /// Pack is done according to the given [params].
    ///
    /// The default config performs repudiable encryption
    /// ([AuthCryptAlg] if [PackEncryptedParams.from] is set and [AnonCryptAlg] otherwise)
    /// and prepares a message for forwarding to the returned endpoint (via Forward protocol).
    ///
    /// It's possible to add non-repudiation by providing [PackEncryptedParams.signFrom] argument (DID or key ID).
    /// Signed messages are only necessary when
    ///  - the origin of plaintext must be provable to third parties;
    ///  - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
    ///    is not known in advance (e.g., in a broadcast scenario).
    ///
    /// Adding a signature when one is not needed can degrade rather than enhance security because it
    /// relinquishes the sender’s ability to speak off the record.
    ///
    /// Encryption is done as follows:
    ///  - encryption is done via the keys from the [keyAgreements] verification relationship in the DID Doc;
    ///  - if [PackEncryptedParams.from] is `null`, then anonymous encryption is done
    ///    Otherwise authenticated encryption is done;
    ///  - if [PackEncryptedParams.from] is a DID, then the first sender's [keyAgreements] verification method
    ///    is used which can be resolved via secrets resolver and has the same type as any of recipient keys;
    ///  - if [PackEncryptedParams.from] is a key ID, then the sender's [keyAgreements] verification method
    ///    identified by the given key ID is used;
    ///  - if [PackEncryptedParams.to] is a DID, then multiplex encryption is done for all keys from the receiver's [keyAgreements]
    ///    verification relationship which have the same type as the sender's key;
    ///  - if  [PackEncryptedParams.to] is a key ID, then encryption is done for the receiver's [keyAgreements]
    ///    verification method identified by the given key ID.
    ///
    /// If non-repudiation (signing) is added by specifying a [PackEncryptedParams.signFrom] argument:
    ///  - Signing is done via the keys from the [authentications] verification relationship
    ///    in the DID Doc for the DID to be used for signing;
    ///  - If [PackEncryptedParams.signFrom] is a DID, then the first sender's [authentications]
    ///    verification method is used for which a private key in the secrets resolver is found;
    ///  - If [PackEncryptedParams.signFrom] is a key ID, then the sender's [authentications]
    ///    verification method identified by the given key ID is used.
    /// </summary>
    /// <param name="param"></param>
    /// <returns></returns>
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
        var didServicesChain = await Routing.ResolveDidCommServicesChain(
            didDocResolver, param.To, param.ForwardServiceId
        );

        var wrapInForwardResult = await PackEncrypt.WrapInForwardIfNeeded(
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

    /// <summary>
    /// Unpacks the packed DIDComm message by doing decryption and verifying the signatures.
    /// </summary>
    /// <param name="param"></param>
    /// <returns></returns>
    public async Task<Result<UnpackResult>> Unpack(UnpackParams param)
    {
        var didDocResolver = param.IdidDocResolver ?? this._didDocResolver;
        var secretResolver = param.SecretResolver ?? this._secretResolver;
        var recipientKeySelector = new RecipientKeySelector(didDocResolver, secretResolver);

        return await Unpacker.Unpack(param, recipientKeySelector);
    }
}