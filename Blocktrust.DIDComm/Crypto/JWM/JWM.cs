namespace Blocktrust.DIDComm.Crypto.JWM;

using Message.Messages;

// using Model.UnpackResultModels;

public sealed class JwmParseResult : ParseResult
{
    public static ParseResult Parse(Dictionary<string, object> json)
    {
        if (json.ContainsKey("signatures"))
            return new JwsParseResult(json);
        else if (json.ContainsKey("recipients"))
            return new JweParseResult(json);
        else
            return new JwmParseResult(Message.Parse(json));
    }


    public readonly Message Message;

    public JwmParseResult(Message message)
    {
        this.Message = message;
    }


}