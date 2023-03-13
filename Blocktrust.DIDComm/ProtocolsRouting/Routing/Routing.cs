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

    private IDidDocResolver _ididDocResolver;
    private ISecretResolver _secretResolver;

    public Routing(IDidDocResolver ididDocResolver, ISecretResolver secretResolver)
    {
        this._ididDocResolver = ididDocResolver;
        this._secretResolver = secretResolver;
    }


    public static async Task<List<Service>> ResolveDidCommServicesChain(
        IDidDocResolver ididDocResolver,
        string to,
        string serviceId = null,
        bool didRecursion = false
    )
    {
        var toDidService = await FindDidCommService(ididDocResolver, to, serviceId);
        if (toDidService == null) return new List<Service>();

        var res = new List<Service>();
        var serviceUri = toDidService.ServiceEndpoint;

        res.Insert(0, toDidService);

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

            var mediatorDidService = await FindDidCommService(ididDocResolver, mediatorDid);
            if (mediatorDidService == null)
            {
                throw new DidCommServiceException(
                    mediatorDid, "mediator '" + mediatorDid + "' service doc not found"
                );
            }

            serviceUri = mediatorDidService.ServiceEndpoint;
            res.Insert(0, mediatorDidService);
        }

        return res;
    }

    internal static async Task<Service?> FindDidCommService(
        IDidDocResolver ididDocResolver,
        string to,
        string? serviceId = null
    )
    {
        string toDid = DidUtils.GetDid(to);
        // TODO this copy() is not needed for single tests, but not having it breaks the tests when running in parallel
        // This issue has to be investigated and cleared up before merging

        DidDoc? didDoc = await ididDocResolver.Resolve(toDid).Copy();
        if (didDoc is null)
        {
            throw new DidDocNotResolvedException(toDid);
        }

        if (serviceId != null)
        {
            Service didService = didDoc.FindDidCommService(serviceId);

            if (didService.Accept != null && didService.Accept.Any() && !didService.Accept.Contains(PROFILE_DIDCOMM_V2))
            {
                throw new DidCommServiceException(
                    toDid, $"service '{serviceId}' does not accept didcomm/v2 profile"
                );
            }

            return didService;
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
                return didDoc.Services.FirstOrDefault(it => it.Accept == null || !it.Accept.Any() || it.Accept.Contains(PROFILE_DIDCOMM_V2));
            }
            catch (DidDocException e)
            {
                return null;
            }
        }
    }

    public async Task<WrapInForwardResult> WrapInForward(
        Dictionary<string, object> packedMsg,
        string to,
        AnonCryptAlg encAlgAnon = null,
        List<string> routingKeys = null,
        Dictionary<string, object> headers = null,
        IDidDocResolver? didDocResolver = null,
        ISecretResolver? secretResolver = null
    )
    {
        if (routingKeys == null || routingKeys.Count == 0)
            return null;

        var _didDocResolver = didDocResolver ?? this._ididDocResolver;
        var _secretResolver = secretResolver ?? this._secretResolver;
        var keySelector = new SenderKeySelector(_didDocResolver, _secretResolver);

        // TODO
        //  - headers validation against ForwardMessage
        //  - logging
        //  - id generator as an argument

        ForwardMessage fwdMsg = null;
        var forwardedMsg = packedMsg;
        EncryptResult encryptedResult = null;

        //TODO I don't know if this is correct. but it holds some at least one test
        var tos = routingKeys.ToList();
        routingKeys.Reverse();
        var nexts = routingKeys.Skip(1).ToList();
        nexts.Add(to);
        nexts.Reverse();

        // wrap forward msgs in reversed order so the message to final
        // recipient 'to' will be the innermost one
        var toNextZipped = tos.Zip(nexts).ToList();

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
            )).Item1;

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
        IDidDocResolver ididDocResolver = didDocResolver ?? this._ididDocResolver;
        ISecretResolver _secretResolver = secretResolver ?? this._secretResolver;
        RecipientKeySelector recipientKeySelector = new RecipientKeySelector(ididDocResolver, _secretResolver);

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