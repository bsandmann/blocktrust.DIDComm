namespace Blocktrust.DIDComm.Message.Attachments;

using System.Text.Json.Serialization;
using Exceptions;

public interface IData
{
    [JsonPropertyName("hash")]
    public string Hash { get; }
    [JsonPropertyName("jws")]
    public Dictionary<string, object> Jws { get; }


    public abstract Dictionary<string, object> ToJsonObject();

    public static IData Parse(Dictionary<string, object> json)
    {
        if (json.ContainsKey(Header.Json))
        {
            return Json.Parse(json);
        }
        if (json.ContainsKey(Header.Links))
        {
            return Links.Parse(json);
        }
        if (json.ContainsKey(Header.Base64))
        {
            return Base64.Parse(json);
        }
        throw new MalformedMessageException("Unknown attachment data");
    }
}