namespace Blocktrust.DIDComm.Message.Attachments;

using System.Text.Json.Serialization;
using Exceptions;
using Utils;

public class Links : IData
{
    [JsonPropertyName("links")] public List<string> LinksString { get; set; }
    [JsonPropertyName("hash")] public string? Hash { get; set; }
    [JsonPropertyName("jws")] public Dictionary<string, object>? Jws { get; set; }

    [JsonConstructor]
    public Links()
    {
    }

    public Links(List<string> linksString, string? hash = null, Dictionary<string, object>? jws = null)
    {
        this.LinksString = linksString;
        this.Hash = hash;
        this.Jws = jws;
    }

    public static IData Parse(Dictionary<string, object> json)
    {
        var links = json.GetTypedArray<string>(Header.Links)
            .Where(x => x != null)
            .ToList();
        if (links == null)
        {
            throw new MalformedMessageException("The header \"" + Header.Links + "\" is missing");
        }

        var hash = json.GetTyped<string>(Header.Hash);
        if (hash == null)
        {
            throw new MalformedMessageException("The header \"" + Header.Hash + "\" is missing");
        }

        var jws = json.GetTyped<Dictionary<string, object>>(Header.Jws);

        return new Links
        (
            links,
            hash,
            jws
        );
    }

    public Dictionary<string, object> ToJsonObject()
    {
        return new Dictionary<string, object>
        {
            { Header.Jws, Jws },
            { Header.Hash, Hash },
            { Header.Links, LinksString }
        };
    }
}