namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Converter;
using Exceptions;
using JWE;
using Utils;

public class MultibasePublicKey : Key
{
    public string Id { get; set; }
    public Jwk Jwk { get; set; }
    public Curve Curve { get; set; }
    
    public MultibasePublicKey(string id, string curve, string materialValue)
    {
        this.Id = id;
        var prefixedRawValue = Multibase.Decode(materialValue);
        (Multicodec codec, byte[] rawValue) = Multicodec.FromMulticodec(prefixedRawValue);
        var expectedCodec = curve switch
        {
            Curve.CurveNameX25519 => Multicodec.X25519Public,
            Curve.CurveNameEd25519 => Multicodec.Ed25519Public,
            _ => throw new UnsupportedCurveException(curve)
        };
        if (codec.PrefixInt != expectedCodec.PrefixInt)
        {
            throw new ArgumentException($"Multicoded prefix {codec.ToString()} is not valid for publicKeyMultibase and {curve} curve");
        }
        string base64URLValue = Base64Url.Encode(rawValue);
        var jwkJson = new Dictionary<string, object>
        {
            ["kty"] = "OKP",
            ["crv"] = curve,
            ["x"] = base64URLValue
        };
        
        var jwk = new Jwk();
        jwk.Kty = "OKP";
        jwk.Crv = curve;
        jwk.X = base64URLValue;
        
        if (!Key.IsCurveBased(jwk))
        {
            throw new UnsupportedJwkException(jwk.GetType().Name);
        }

        this.Jwk = jwk;
        this.Curve = Curve.Parse(jwk.Crv);
    }
}