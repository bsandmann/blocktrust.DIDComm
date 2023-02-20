namespace Blocktrust.DIDComm.Operations;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;
using Crypto.JWE;
using Crypto.JWS;
using Crypto.Keys;
using Model.PackEncryptedParamsModels;
using ProtocolsRouting.Routing;
using Utils;

public class PackEncrypt
{
    public static (string, string?) SignIfNeeded(string message, PackEncryptedParams param, SenderKeySelector keySelector)
    {
        if (param.SignFrom != null)
        {
            var key = keySelector.FindSigningKey(param.SignFrom);
            return (Jws.Sign(message, key), key.Id);
        }
        else
        {
            return (message, null);
        }
    }

    public static (EncryptResult, List<Key>) Encrypt(PackEncryptedParams param, string payload, SenderKeySelector keySelector)
    {
        if (param.From != null)
        {
            (var senderKey, var recipientKeys) = keySelector.FindAuthCryptKeys(param.From, param.To);
            return (JweExtensions.AuthEncrypt(payload, param.EncAlgAuth, senderKey, recipientKeys), recipientKeys);
        }
        else
        {
            var recipientKeys = keySelector.FindAnonCryptKeys(param.To);
            return (JweExtensions.AnonEncrypt(payload, param.EncAlgAnon, recipientKeys), recipientKeys);
        }
    }

    public static EncryptResult ProtectSenderIfNeeded(PackEncryptedParams param, EncryptResult encryptResult, List<Key> recipientKeys)
    {
        if (param.ProtectSenderId && param.From != null)
        {
            return (JweExtensions.AnonEncrypt(encryptResult.PackedMessage, param.EncAlgAnon, recipientKeys));
        }
        else
        {
            return encryptResult;
        }
    }

    public static WrapInForwardResult? WrapInForwardIfNeeded(
        string packedMessage,
        PackEncryptedParams param,
        List<Service> didServicesChain,
        IDidDocResolver ididDocResolver,
        ISecretResolver secretResolver)
    {
        if (!(param.Forward && didServicesChain.Count > 0))
        {
            return null;
        }

        List<string> routingKeys = didServicesChain.Last().RoutingKeys;

        if (routingKeys.Count == 0)
        {
            return null;
        }

        if (didServicesChain.Count > 1)
        {
            routingKeys.AddRange(didServicesChain.Skip(1).Select(it => it.ServiceEndpoint).ToList());
        }

        var r = new Routing(ididDocResolver, secretResolver);
        return r.WrapInForward(
            JsonUtils.FromJsonToMap(packedMessage),
            param.To,
            param.EncAlgAnon,
            routingKeys,
            param.ForwardHeaders
        );
    }
}