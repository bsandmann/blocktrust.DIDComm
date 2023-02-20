namespace Blocktrust.DIDComm.Crypto.Keys;

using JWE;

public class JsonWebKey : Key
{
    public string Id { get; set; }
    public Jwk Jwk { get; set; }
    public Curve Curve { get; set; }

    public JsonWebKey(string id, string materialValue)
    {
        var deserializedJwk = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(materialValue);
        var jwk = Jwk.FromDictionary(deserializedJwk.ToDictionary(x => x.Key, x => (object)x.Value));

        this.Id = id;
        this.Jwk = jwk;
        this.Curve = Curve.Parse(jwk.Crv);
    }
}