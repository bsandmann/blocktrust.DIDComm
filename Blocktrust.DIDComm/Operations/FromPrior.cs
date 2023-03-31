namespace Blocktrust.DIDComm.Operations;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Crypto.JWT;
using Crypto.Keys;
using Exceptions;
using Message.Messages;
using Utils;

public static class FromPrior
{
    public static async Task<(Message, string?)> PackFromPrior(
        Message message,
        string? fromPriorIssuerKid,
        SenderKeySelector keySelector)
    {
        // Make a deep copy of the message
        var messageCopy =  message.Copy();
        
        if (messageCopy.FromPrior is not null)
        {
            var key = await keySelector.FindSigningKey(fromPriorIssuerKid ?? messageCopy.FromPrior.Iss);

            messageCopy.FromPriorJwt = Jwt.SignJwt(messageCopy.FromPrior!.ToJsonObject(), key);
            messageCopy.FromPrior = null;

            return (messageCopy, key.Id);
        }
        else
        {
            return (messageCopy, null);
        }
    }

    public static async Task<(Message, string?)> UnpackFromPrior(Message message, RecipientKeySelector keySelector)
    {
        // Make a deep copy of the message
        var messageCopy = message.Copy();
        
        if (messageCopy.FromPriorJwt is not null)
        {
            var issKid = ExtractFromPriorKid(messageCopy.FromPriorJwt);
            var key = await keySelector.FindVerificationKey(issKid);
            var verified = Jwt.VerifyJwt(messageCopy.FromPriorJwt, key);
            messageCopy.FromPrior = (DIDComm.Message.FromPriors.FromPrior.Parse(verified));
            messageCopy.FromPriorJwt = null;
            return (messageCopy, key.Id);
        }
        else
        {
            return (messageCopy, null);
        }
    }

    private static string ExtractFromPriorKid(string fromPriorJwt)
    {
        string[] segments = fromPriorJwt.Split(".");
        if (segments.Length != 3)
        {
            throw new MalformedMessageException("JWT cannot be deserialized");
        }

        var decodedHeader = Base64Url.Decode(segments[0]);
        var header = Encoding.UTF8.GetString(decodedHeader);
        Dictionary<string, object>? jwsHeader = JsonSerializer.Deserialize<Dictionary<string, object>>(header);
        if (jwsHeader == null)
        {
            throw new MalformedMessageException("JWT cannot be deserialized");
        }
        var kidHeader = jwsHeader["kid"];
        var kidHeaderAsJsonElement = (JsonElement)kidHeader;
        if(kidHeaderAsJsonElement.ValueKind == JsonValueKind.String)
        {
            var kidHeaderString = kidHeaderAsJsonElement.GetString();
            return kidHeaderString ?? string.Empty;
        }
        else
        {
            throw new MalformedMessageException("JWT kid cannot be deserialized");
        }
    }
}