namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Converter;
using Exceptions;
using JWE;
using Utils;

class Base58PrivateKey : Key
{
    public string Id { get; set; }
    public Jwk Jwk { get; set; }
    public Curve Curve { get; set; }

    public Base58PrivateKey(string id, string curve, string materialValue)
    {
        this.Id = id;
        Span<byte> rawValue = Multibase.Decode(materialValue, Multibase.BASE58_BTC_Name);

        var rawValueD = rawValue.Slice(0, Key.Curve25519PointSize);
        var rawValueX = rawValue.Slice(Key.Curve25519PointSize);

        var base64URLValueD = Base64Url.Encode(rawValueD.ToArray());
        var base64URLValueX = Base64Url.Encode(rawValueX.ToArray());

        var jwkJson = new Dictionary<string, object>
        {
            { "kty", "OKP" },
            { "crv", curve },
            { "x", base64URLValueX },
            { "d", base64URLValueD }
        };
        var jwk = new Jwk();
        jwk.Kty = "OKP";
        jwk.Crv = curve;
        jwk.X = base64URLValueX;
        jwk.D = base64URLValueD;

        if (!Key.IsCurveBased(jwk))
            throw new UnsupportedJwkException(jwk.GetType().Name);

        this.Jwk = jwk;
        this.Curve = Curve.Parse(jwk.Crv);
    }
}