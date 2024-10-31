namespace Blocktrust.DIDComm.Operations;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;
using Crypto.JWE;
using Crypto.JWS;
using Crypto.Keys;
using FluentResults;
using Model.PackEncryptedParamsModels;
using ProtocolsRouting.Routing;
using Utils;

public static class PackEncrypt
{
    public static async Task<Result<(string, string?)>> SignIfNeeded(string message, PackEncryptedParams param, SenderKeySelector keySelector)
    {
        if (param.SignFrom != null)
        {
            var keyResult = await keySelector.FindSigningKey(param.SignFrom);
            if (keyResult.IsFailed)
            {
                return keyResult.ToResult();
            }

            return (Jws.Sign(message, keyResult.Value), keyResult.Value.Id);
        }
        else
        {
            return (message, null);
        }
    }

    public static async Task<Result<(EncryptResult, List<Key>)>> Encrypt(PackEncryptedParams param, string payload, SenderKeySelector keySelector)
    {
        if (param.From != null)
        {
            var findAuthCryptKeysResult = await keySelector.FindAuthCryptKeys(param.From, param.To);
            if (findAuthCryptKeysResult.IsFailed)
            {
                return findAuthCryptKeysResult.ToResult();
            }

            var (senderKey, recipientKeys) = findAuthCryptKeysResult.Value;
            return (JweExtensions.AuthEncrypt(payload, param.EncAlgAuth, senderKey, recipientKeys), recipientKeys);
        }
        else
        {
            var recipientKeysResult = await keySelector.FindAnonCryptKeys(param.To);
            if (recipientKeysResult.IsFailed)
            {
                return recipientKeysResult.ToResult();
            }
            return (JweExtensions.AnonEncrypt(payload, param.EncAlgAnon, recipientKeysResult.Value), recipientKeysResult.Value);
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

    public static async Task<WrapInForwardResult?> WrapInForwardIfNeeded(
        string packedMessage,
        PackEncryptedParams param,
        List<Service> didServicesChain,
        IDidDocResolver didDocResolver,
        ISecretResolver secretResolver)
    {
        if (!(param.Forward && didServicesChain.Count > 0))
        {
            return null;
        }

        List<string> routingKeys = didServicesChain.Last().ServiceEndpoint.RoutingKeys;

        if (routingKeys.Count == 0)
        {
            return null;
        }

        if (didServicesChain.Count > 1)
        {
            routingKeys.AddRange(didServicesChain.Skip(1).Select(it => it.ServiceEndpoint.Uri).ToList());
        }

        var r = new Routing(didDocResolver, secretResolver);
        return await r.WrapInForward(
            JsonUtils.FromJsonToMap(packedMessage),
            param.To,
            param.EncAlgAnon,
            routingKeys,
            param.ForwardHeaders
        );
    }
}