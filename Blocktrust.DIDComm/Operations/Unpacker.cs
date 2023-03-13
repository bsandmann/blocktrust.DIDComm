namespace Blocktrust.DIDComm.Operations;

using Crypto.JWE;
using Crypto.JWM;
using Crypto.JWS;
using Crypto.Keys;
using Exceptions;
using FluentResults;
using Message.Messages;
using Model.UnpackParamsModels;
using Model.UnpackResultModels;

public class Unpacker
{
    public static async Task<Result<UnpackResult>> Unpack(UnpackParams param, RecipientKeySelector keySelector)
    {
        try
        {
            var packedMessage = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(param.PackedMessage);
            var metadataBuilder = new UnpackResultBuilder();
            var msg = await Unpack(
                packedMessage,
                keySelector,
                metadataBuilder,
                param.ExpectDecryptByAllKeys,
                param.UnwrapReWrappingForward
            );
            return Result.Ok(new UnpackResult(msg, metadataBuilder.BuildUnpackResult()));
        }
        catch (Exception e)
        {
            return Result.Fail($"Message cannot be parsed: {e.Message}");
        }
    }

    public static async Task<Message> Unpack(
        Dictionary<string, object?> packedMessage,
        RecipientKeySelector keySelector,
        UnpackResultBuilder metadataUnpackResultBuilder,
        bool expectDecryptByAllKeys,
        bool unwrapReWrappingForward)
    {
        var parseResult = JwmParseResult.Parse(packedMessage);
        if (parseResult is JwsParseResult)
        {
            return await Jws.Unpack(((JwsParseResult)parseResult), keySelector, metadataUnpackResultBuilder);
        }
        else if (parseResult is JweParseResult)
        {
            return (await JweExtensions.Unpack((JweParseResult)parseResult, keySelector, expectDecryptByAllKeys, metadataUnpackResultBuilder, unwrapReWrappingForward)).Item1;
        }
        else if (parseResult is JwmParseResult)
        {
            return await JwmExtensions.Unpack((JwmParseResult)parseResult, keySelector, metadataUnpackResultBuilder);
        }

        throw new Exception("Unable to unpack message");
    }
}