namespace Blocktrust.DIDComm.Crypto.JWS;

using Blocktrust.Common.Converter;
using JWE;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

public static class ECDSA
{
    public static byte[] Sign(byte[] message, Jwk key)
    {
        X9ECParameters ecParams = null;
        if (key.Crv == "secp256k1")
        {
            ecParams = SecNamedCurves.GetByName("secp256k1");
        }
        else if (key.Crv == "P-256")
        {
            ecParams = SecNamedCurves.GetByName("secp256r1");
        }
        else
        {
            throw new Exception("Curve not supported");
        }

        var publicKeyQ = ECUtils.GeneratePublicKeyByteArray(key);
        var curve = ecParams.Curve;
        var g = ecParams.G;
        var n = ecParams.N;
        BigInteger d = new BigInteger(1, Base64Url.Decode(key.D));
        var privateKeyX = new ECPrivateKeyParameters(d, new ECDomainParameters(curve, g, n));
        var publicKEyX = new ECPublicKeyParameters(publicKeyQ, new ECDomainParameters(curve, g, n));
        // Bouncy castle supports the option to convert the DER signature directly to the required 64-byte format required
        // for the tokes. The standard "SHA256withECDSA" Algorithm has otherwise to be converted to a ASN1 format and theoretically
        // should work also in the validation, but I had issues validating the resulting 64 byte signature
        var signerAlgorithm = "SHA-256withPLAIN-ECDSA";
        var keyParameter = new AsymmetricCipherKeyPair(publicKEyX, privateKeyX);
        ISigner signer = SignerUtilities.GetSigner(signerAlgorithm);
        signer.Init(true, keyParameter.Private);
        signer.BlockUpdate(message, 0, message.Length);
        byte[] signature = signer.GenerateSignature();
        return signature;
    }

    public static bool Verify(byte[] message, Jwk key, byte[] signature)
    {
        X9ECParameters ecParams = null;
        if (key.Crv == "secp256k1")
        {
            ecParams = SecNamedCurves.GetByName("secp256k1");
        }
        else if (key.Crv == "P-256")
        {
            ecParams = SecNamedCurves.GetByName("secp256r1");
        }
        else
        {
            throw new Exception("Curve not supported");
        } 
        
        ISigner signer2 = SignerUtilities.GetSigner("SHA-256withPLAIN-ECDSA");
        var publicKeyQ = ECUtils.GeneratePublicKeyByteArray(key);
        var curve = ecParams.Curve;
        var g = ecParams.G;
        var n = ecParams.N;
        var publicKEyX = new ECPublicKeyParameters(publicKeyQ, new ECDomainParameters(curve, g, n));
        signer2.Init(false, publicKEyX);
        signer2.BlockUpdate(message, 0, message.Length);
        var r = signer2.VerifySignature(signature);
        return r;
    }
}