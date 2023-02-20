namespace Blocktrust.DIDComm.Message.Attachments;

public class Json : IData
{
    public Dictionary<string, object> JsonString { get; set; }
    public string Hash { get; set; }
    public Dictionary<string, object> Jws { get; set; }

    public Json(Dictionary<string, object> json = null, string hash = null, Dictionary<string, object> jws = null)
    {
        this.JsonString = json;
        this.Hash = hash;
        this.Jws = jws;
    }

    public static IData Parse(Dictionary<string, object> json)
    {
        Dictionary<string, object> jsonData = null;
        if (json.ContainsKey(Header.Json))
        {
            jsonData = json;
        }
        else
        {
            jsonData = json;
            // throw new MalformedMessageException($"The header \"{Header.Json}\" is missing");
        }

        var hash = json.ContainsKey(Header.Hash) ? json[Header.Hash] as string : null;
        var jws = json.ContainsKey(Header.Jws) ? json[Header.Jws] as Dictionary<string, object> : null;

        return new Json(jsonData, hash, jws);
    }

    public Dictionary<string, object> ToJsonObject()
    {
        return new Dictionary<string, object>()
        {
            { Header.Jws, Jws },
            { Header.Hash, Hash },
            { Header.Json, JsonString },
        };
    }
}