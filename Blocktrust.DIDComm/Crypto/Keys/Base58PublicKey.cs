namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Converter;
using Exceptions;
using JWE;
using Utils;

public class Base58PublicKey : Key
{
    public string Id { get; set; }
    public Jwk Jwk { get; set; }
    public Curve Curve { get; set; }
    
    public Base58PublicKey(string id, string curve, string materialValue)
    {
        this.Id = id;
        byte[] rawValue = Multibase.Decode(materialValue, Multibase.BASE58_BTC_Name);
        string base64URLValue = Base64Url.Encode(rawValue);

        Dictionary<string, object> jwkJson = new Dictionary<string, object>
        {
            { "kty", "OKP" },
            { "crv", curve },
            { "x", base64URLValue }
        };
        var jwk = new Jwk();
        jwk.Kty = "OKP";
        jwk.Crv = curve;
        jwk.X = base64URLValue;
        
        if (!Key.IsCurveBased(jwk))
            throw new UnsupportedJwkException(jwk.GetType().Name);

        this.Jwk = jwk;
        this.Curve = Curve.Parse(jwk.Crv);
    }

}