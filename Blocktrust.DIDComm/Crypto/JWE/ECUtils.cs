namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

public static class ECUtils
{
    /// <summary>
    /// Given a X and Y Value of PublicKey, generate the combined key Q (65byte array)
    /// </summary>
    /// <returns></returns>
    public static ECPoint GeneratePublicKeyByteArray(Jwk epk)
    {
        X9ECParameters ecParams;
        if (epk.Crv == "secp256k1")
        {
            ecParams = SecNamedCurves.GetByName("secp256k1");
        }
        else if (epk.Crv == "P-256")
        {
            ecParams = SecNamedCurves.GetByName("secp256r1");
        }
        else if (epk.Crv == "P-384")
        {
            ecParams = SecNamedCurves.GetByName("secp384r1");
        }
        else if (epk.Crv == "P-521")
        {
            ecParams = SecNamedCurves.GetByName("secp521r1");
        }
        else
        {
            throw new NotImplementedException();
        }

        ECCurve curve = ecParams.Curve;
        var x = new BigInteger(1,Base64Url.Decode(epk.X));
        var y = new BigInteger(1, Base64Url.Decode(epk.Y));
        
        return curve.CreatePoint(x,y);
    }
}