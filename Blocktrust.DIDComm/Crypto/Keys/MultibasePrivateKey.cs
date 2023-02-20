namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Converter;
using Exceptions;
using JWE;
using Utils;

class MultibasePrivateKey : Key
{
    public string Id { get; set; }
    public Jwk Jwk { get; set; }
    public Curve Curve { get; set; }

    public MultibasePrivateKey(string id, string curve, string materialValue)
    {
        this.Id = id;
        var prefixedRawValue = Multibase.Decode(materialValue);
        var (codec,  rawValue) = Multicodec.FromMulticodec(prefixedRawValue);
        var rawValueSpan = new Span<byte>(rawValue);

        Multicodec expectedCodec = curve switch
        {
            Curve.CurveNameX25519 => Multicodec.X25519Private,
            Curve.CurveNameEd25519 => Multicodec.Ed25519Private,
            _ => throw new UnsupportedCurveException(curve)
        };

        if (codec.PrefixInt != expectedCodec.PrefixInt)
        {
            throw new ArgumentException(
                $"Multicoded prefix {codec.ToString()} is not valid for publicKeyMultibase and {curve} curve"
            );
        }

        var rawValueD = rawValueSpan.Slice(0, Key.Curve25519PointSize);
        var rawValueX = rawValueSpan.Slice(Key.Curve25519PointSize);

        var base64URLValueD = Base64Url.Encode(rawValueD.ToArray()).ToString();
        var base64URLValueX = Base64Url.Encode(rawValueX.ToArray()).ToString();

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
        {
            throw new UnsupportedJwkException(jwk.GetType().Name);
        }

        this.Jwk = jwk;
        this.Curve = Curve.Parse(jwk.Crv);
    }
}