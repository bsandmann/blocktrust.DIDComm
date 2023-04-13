namespace Blocktrust.DIDComm.Message.FromPriors;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using Exceptions;
using Utils;

public class FromPrior
{
    [JsonPropertyName("iss")] public string Iss { get; set; }
    [JsonPropertyName("sub")] public string Sub { get; set; }
    [JsonPropertyName("aud")] public string? Aud { get; set; }
    [JsonPropertyName("exp")] public long? Exp { get; set; }
    [JsonPropertyName("nbf")] public long? Nbf { get; set; }
    [JsonPropertyName("iat")] public long? Iat { get; set; }
    [JsonPropertyName("jti")] public string? Jti { get; set; }

    [JsonConstructor]
    public FromPrior()
    {
        // Need for deserialization
    }

    public FromPrior(FromPriorsBuilder fromPriorsBuilder)
    {
        this.Iss = fromPriorsBuilder.Iss;
        this.Sub = fromPriorsBuilder.Sub;
        this.Aud = fromPriorsBuilder.aud;
        this.Exp = fromPriorsBuilder.exp;
        this.Nbf = fromPriorsBuilder.nbf;
        this.Iat = fromPriorsBuilder.iat;
        this.Jti = fromPriorsBuilder.jti;
    }

    public static FromPriorsBuilder Builder(string iss, string sub) => new FromPriorsBuilder(iss, sub);

    public static FromPrior Parse(Dictionary<string, object> json)
    {
        if (json == null)
        {
            return null;
        }

        if (!json.TryGetValue(Header.Iss, out var iss))
        {
            throw new MalformedMessageException("The header \"" + Header.Iss + "\" is missing");
        }

        if (!json.TryGetValue(Header.Sub, out var sub))
        {
            throw new MalformedMessageException("The header \"" + Header.Sub + "\" is missing");
        }

        if (iss is null)
        {
            throw new MalformedMessageException("The header \"" + Header.Iss + "\" is invalid");
        }

        if (sub is null)
        {
            throw new MalformedMessageException("The header \"" + Header.Sub + "\" is invalid");
        }

        var builder = Builder((string)iss, (string)sub);

        foreach (var (key, value) in json)
        {
            switch (key)
            {
                case "iss":
                case "sub":
                    break;
                case "aud":
                    if (value is not null)
                    {
                        builder.Aud((string)value);
                    }
                    break;
                case "exp":
                
                    builder.Exp(long.Parse(value.ToString()));
                    break;
                case "nbf":
                 
                    builder.Nbf(long.Parse(value.ToString()));
                    break;
                case "iat":
                  
                    builder.Iat(long.Parse(value.ToString()));
                    break;
                case "jti":
                  
                    if (value is not null)
                    {
                        builder.Jti((string)value);
                    }

                    break;
                default:
                    throw new MalformedMessageException("Unknown from_prior's header: " + key);
            }
        }

        return builder.Build();
    }


    public Dictionary<string, object?> ToJsonObject()
    {
        return new Dictionary<string, object?>
        {
            { Header.Iss, Iss },
            { Header.Sub, Sub },
            { Header.Aud, Aud },
            { Header.Exp, Exp },
            { Header.Nbf, Nbf },
            { Header.Iat, Iat },
            { Header.Jti, Jti }
        }.Where(kvp => kvp.Value != null).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
    }

    public override string ToString() => ToJsonObject().ToJsonString();
}