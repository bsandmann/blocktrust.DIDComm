namespace Blocktrust.DIDComm.Crypto.JWM;

using Exceptions;
using JWS;

public sealed class JwsParseResult : ParseResult
{
    // private readonly JWS message;
    //TODO unlcear. Something that represent a JWS
    //in kotlin this is a seperate object, not existing in my lib
    //Maybe i need thsi package? System.IdentityModel.Tokens.Jwt?
    //https://stackoverflow.com/questions/38340078/how-to-decode-jwt-token
    
    public readonly JwsObject Token;

    public JwsParseResult(Dictionary<string, object> rawMessage)
    {
        try
        {
            this.Token = JwsObject.Parse(rawMessage);
            this.RawMessage = rawMessage; //?????
        }
        catch (Exception e)
        {
            throw new MalformedMessageException($"Message cannot be parsed: {e.Message}");
        }
    }
}