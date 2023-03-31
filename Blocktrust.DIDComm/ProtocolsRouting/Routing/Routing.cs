namespace Blocktrust.DIDComm.ProtocolsRouting.Routing;

using Blocktrust.Common.Exceptions;
using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;
using Common.Algorithms;
using Crypto.JWE;
using Crypto.Keys;
using Exceptions;
using FluentResults;
using ForwardMessages;
using Model.PackEncryptedParamsModels;
using Model.PackEncryptedResultModels;
using Model.UnpackParamsModels;
using Model.UnpackResultModels;
using Operations;
using Utils;

public class Routing
{
    public const string PROFILE_DIDCOMM_AIP2_ENV_RFC587 = "didcomm/aip2;env=rfc587";
    public const string PROFILE_DIDCOMM_V2 = "didcomm/v2";

    private readonly IDidDocResolver _didDocResolver;
    private readonly ISecretResolver _secretResolver;

    public Routing(IDidDocResolver didDocResolver, ISecretResolver secretResolver)
    {
        this._didDocResolver = didDocResolver;
        this._secretResolver = secretResolver;
    }


    public static async Task<Result<List<Service>>> ResolveDidCommServicesChain(
        IDidDocResolver didDocResolver,
        string to,
        string? serviceId = null,
        bool didRecursion = false
    )
    {
        var toDidService = await FindDidCommService(didDocResolver, to, serviceId);
        if (toDidService.IsFailed)
        {
            return toDidService.ToResult();
        }

        if (toDidService.Value is null)
        {
            return new List<Service>();
        }

        var res = new List<Service>();
        var serviceUri = toDidService.Value.ServiceEndpoint;

        res.Insert(0, toDidService.Value);

        while (DidUtils.IsDidOrDidUrl(serviceUri))
        {
            var mediatorDid = serviceUri;

            if (res.Count > 1)
            {
                var errMsg = (
                    "mediator '" + res.Last().ServiceEndpoint + "' defines alternative" +
                    " endpoint '" + serviceUri + "' recursively"
                );

                if (didRecursion)
                {
                    throw new NotImplementedException(errMsg);
                }
                else
                {
                    throw new DidCommServiceException(res.Last().ServiceEndpoint, errMsg);
                }
            }

            var mediatorDidService = await FindDidCommService(didDocResolver, mediatorDid);
            if (mediatorDidService.IsFailed)
            {
                return mediatorDidService.ToResult();
            }
            if (mediatorDidService.Value is null)
            {
                return Result.Fail("mediator '" + mediatorDid + "' service doc not found");
            }

            serviceUri = mediatorDidService.Value.ServiceEndpoint;
            res.Insert(0, mediatorDidService.Value);
        }

        return Result.Ok(res);
    }

    private static async Task<Result<Service?>> FindDidCommService(
        IDidDocResolver didDocResolver,
        string to,
        string? serviceId = null
    )
    {
        string toDid = DidUtils.GetDid(to);
        // TODO this copy() is not needed for single tests, but not having it breaks the tests when running in parallel
        // This issue has to be investigated and cleared up before merging

        DidDoc? didDoc = await didDocResolver.Resolve(toDid).Copy();
        if (didDoc is null)
        {
            return Result.Fail($"Unable to resolve DID '{toDid}'");
        }

        if (serviceId != null)
        {
            Service didService = didDoc.FindDidCommService(serviceId);

            if (didService.Accept != null && didService.Accept.Any() && !didService.Accept.Contains(PROFILE_DIDCOMM_V2))
            {
                return Result.Fail($"service '{serviceId}' does not accept didcomm/v2 profile");
            }

            return Result.Ok<Service?>(didService);
        }
        else
        {
            // Find the first service accepting `didcomm/v2` profile because the spec states:
            // > Entries SHOULD be specified in order of receiver preference,
            // > but any endpoint MAY be selected by the sender, typically
            // > by protocol availability or preference.
            // https://identity.foundation/didcomm-messaging/spec/#multiple-endpoints
            try
            {
                return Result.Ok(didDoc.Services.FirstOrDefault(it => it.Accept == null || !it.Accept.Any() || it.Accept.Contains(PROFILE_DIDCOMM_V2)));
            }
            catch (DidDocException e)
            {
                return Result.Ok<Service?>(null);
            }
        }
    }

    public async Task<WrapInForwardResult> WrapInForward(
        Dictionary<string, object> packedMsg,
        string to,
        AnonCryptAlg? encAlgAnon = null,
        List<string>? routingKeys = null,
        Dictionary<string, object>? headers = null,
        IDidDocResolver? didDocResolver = null,
        ISecretResolver? secretResolver = null
    )
    {
        if (routingKeys is null || routingKeys.Count == 0)
        {
            return null;
        }

        var didDocResolverLocal = didDocResolver ?? _didDocResolver;
        var secretResolverLocal = secretResolver ?? _secretResolver;
        var keySelector = new SenderKeySelector(didDocResolverLocal, secretResolverLocal);

        // TODO
        //  - headers validation against ForwardMessage
        //  - logging
        //  - id generator as an argument

        ForwardMessage? fwdMsg = null;
        var forwardedMsg = packedMsg;
        EncryptResult? encryptedResult = null;

        //TODO I don't know if this is correct. but it holds some at least one test
        var tos = routingKeys.ToList();
        routingKeys.Reverse();
        var next = routingKeys.Skip(1).ToList();
        next.Add(to);
        next.Reverse();

        // wrap forward msgs in reversed order so the message to final
        // recipient 'to' will be the innermost one
        var toNextZipped = tos.Zip(next).ToList();

        for (var i = 0; i < toNextZipped.Count; i++)
        {
            var fwdMsgBuilder = new ForwardMessageBuilder(
                DidUtils.DidCommIdGeneratorDefault(),
                toNextZipped[i].Second,
                forwardedMsg
            );
            if (headers != null)
            {
                foreach (var (name, value) in headers)
                {
                    //TODO
                    fwdMsgBuilder.CustomHeader(name, value);
                }
            }

            fwdMsg = fwdMsgBuilder.BuildForward();

            // TODO improve: do not rebuild each time 'to' is changed
            var packParamsBuilder = PackEncryptedParams.Builder(fwdMsg.Message, toNextZipped[i].First);

            if (encAlgAnon != null)
            {
                packParamsBuilder.EncAlgAnon(encAlgAnon);
            }

            encryptedResult = (await PackEncrypt.Encrypt(
                packParamsBuilder.BuildPackEncryptedParams(), fwdMsg.Message.ToString(), keySelector
            )).Value.Item1;

            //TODO?? correct?
            forwardedMsg = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(encryptedResult.PackedMessage);
        }

        return new WrapInForwardResult(
            fwdMsg!,
            new PackEncryptedResult(
                encryptedResult!.PackedMessage,
                encryptedResult.ToKids,
                encryptedResult.FromKid,
                null,
                null,
                null
            )
        );
    }


    public async Task<Result<UnpackForwardResult>> UnpackForward(
        string packedMessage,
        bool expectDecryptByAllKeys = false,
        IDidDocResolver? didDocResolver = null,
        ISecretResolver? secretResolver = null
    )
    {
        IDidDocResolver didDocResolverLocal = didDocResolver ?? this._didDocResolver;
        ISecretResolver secretResolverLocal = secretResolver ?? this._secretResolver;
        RecipientKeySelector recipientKeySelector = new RecipientKeySelector(didDocResolverLocal, secretResolverLocal);

        var unpackResult = await Unpacker.Unpack(
            new UnpackParamsBuilder(packedMessage)
                .ExpectDecryptByAllKeys(expectDecryptByAllKeys)
                .UnwrapReWrappingForward(false)
                .BuildUnpackParams(),
            recipientKeySelector
        );
        if (unpackResult.IsFailed)
        {
            return unpackResult.ToResult();
        }

        ForwardMessage? forwardMessage = ForwardMessage.FromMessage(unpackResult.Value.Message);

        if (forwardMessage is null)
        {
            return Result.Fail("Invalid forward message");
        }

        return Result.Ok(new UnpackForwardResult(
            forwardMessage,
            unpackResult.Value.Metadata.EncryptedTo));
    }
}