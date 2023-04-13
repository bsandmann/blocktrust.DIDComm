namespace Blocktrust.DIDComm.Message.Attachments;

using System.Text.Json.Serialization;
using Exceptions;
using Utils;

public class Base64 : IData
{
    [JsonPropertyName("base64")] public string Base64String { get; private set; }
    [JsonPropertyName("hash")] public string Hash { get; private set; }
    [JsonPropertyName("jws")] public Dictionary<string, object> Jws { get; private set; }

    [JsonConstructor]
    public Base64()
    {
        
    }
    
    public Base64(string base64, string hash = null, Dictionary<string, object> jws = null)
    {
        this.Base64String = base64;
        this.Hash = hash;
        this.Jws = jws;
    }

    public static IData Parse(Dictionary<string, object> json)
    {
        string base64 = json.GetTyped<string>(Header.Base64);
        if (base64 == null)
        {
            throw new MalformedMessageException("The header \"" + Header.Base64 + "\" is missing");
        }

        string hash = json.GetTyped<string>(Header.Hash);
        Dictionary<string, object> jws = json.GetTyped<Dictionary<string, object>>(Header.Jws);

        return new Base64(base64, hash, jws);
    }


    public Dictionary<string, object> ToJsonObject()
    {
        return new Dictionary<string, object>()
        {
            { Header.Jws, Jws },
            { Header.Hash, Hash },
            { Header.Base64, Base64String }
        };
    }
}