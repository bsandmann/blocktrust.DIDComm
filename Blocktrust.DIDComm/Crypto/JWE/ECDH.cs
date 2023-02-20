namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using Blocktrust.Common.Converter;
using Exceptions;
using JWM;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

public static class ECDH
{
    public static byte[] WrapCek(byte[] cek, byte[] sharedKey)
    {
        var wrapEngine = new AesWrapEngine();
        wrapEngine.Init(true, new KeyParameter(sharedKey));
        var wrapped = wrapEngine.Wrap(cek, 0, cek.Length);
        return wrapped;
    }


    public static AlgorithmMode ResolveAlgorithmMode(string alg)
    {
        //ATTENTION Simimlar code also in ECDH1PU

        if (alg == JweAlgorithmExtension.ECDH_ES_A256KW)
            //or 192KW or 256KW
        {
            return AlgorithmMode.Kw;
        }
        // else if (alg == JweAlgorithmExtension.ECDH_1PU)
        // {
        //     return AlgorithmMode.Direct
        // }
        else
        {
            throw new UnsupportedAlgorithmException("Not supported");
        }
    }


    public static byte[] EncodeDataWithLength(byte[] data)
    {
        byte[] bytes = data;
        byte[] length = BitConverter.GetBytes(bytes.Length).Reverse().ToArray();
        return length.Concat(bytes).ToArray();
    }

    public static byte[] EncodeDataWithLength(string? data)
    {
        if (data is not null)
        {
            byte[] bytes = Base64Url.Decode(data);
            byte[] length = BitConverter.GetBytes(bytes.Length).Reverse().ToArray();
            return length.Concat(bytes).ToArray();
        }

        return new byte[4];
    }

    public static byte[] ComputeAAD(JweHeader jweHeader)
    {
        if (jweHeader.RawJsonString is not null)
        {
            var bytes = Encoding.ASCII.GetBytes(jweHeader.RawJsonString);
            var encoded = Base64Url.Encode(bytes);
            return Encoding.ASCII.GetBytes(encoded);
        }


        return Encoding.ASCII.GetBytes(jweHeader.ToBase64());
    }


    public static byte[] DeriveSharedKey(JweHeader header, byte[] sharedKeyZ)
    {
        //SIMILAR but not identical to the ECDH1PU Version

        //TODO
        //Some checks for stuff not being null

        var sharedKeyLength = 256; //just a assumption TODO check
        string algIdString;
        var algMode = ECDH.ResolveAlgorithmMode(header.GetHeaderAlgorithm());
        if (algMode == AlgorithmMode.Direct)
        {
            throw new NotImplementedException();
            //Get name??
            algIdString = header.GetHeaderEncryption().ToString();
        }
        else if (algMode == AlgorithmMode.Kw)
        {
            //Get name??
            algIdString = header.GetHeaderAlgorithm();
        }
        else
        {
            throw new Exception();
        }


        var algId = ECDH.EncodeDataWithLength(Encoding.ASCII.GetBytes(algIdString));
        var partyUInfo = ECDH.EncodeDataWithLength(header.GetAgreementPartyUInfo());
        var partyVInfo = ECDH.EncodeDataWithLength(header.GetAgreementPartyVInfo());
        var suppPubInfo = BitConverter.GetBytes(sharedKeyLength).Reverse().ToArray();
        var suppPrivInfo = new byte[0];

        var iv = algId.Concat(partyUInfo).Concat(partyVInfo).Concat(suppPubInfo).Concat(suppPrivInfo).ToArray();

        var concatKDF = new ConcatenationKdfGenerator(new Sha256Digest());
        concatKDF.Init(new KdfParameters(sharedKeyZ, iv));
        byte[] result = new byte[32];
        concatKDF.GenerateBytes(result,0,32);
        return result;
    }

    private static JweCryptoParts EncryptWithZ(JweHeader header, byte[] sharedKeyZ, byte[] clearText, byte[] contentEncryptionKey)
    {
        //ATTENTION simimlar but not identical code in ECDH1pu


        //TODO we should use the Header object here and not just the dictionary
        // var agl = (string)header["alg"];
        var alg = header.GetHeaderAlgorithm();
        var algMode = ECDH.ResolveAlgorithmMode(alg);
        var enc = header.GetHeaderEncryption();

        var sharedKey = ECDH.DeriveSharedKey(header, sharedKeyZ);

        byte[] cek = new byte[] { };

        if (algMode == AlgorithmMode.Direct)
        {
            throw new NotImplementedException();
            return null;
        }
        else if (algMode == AlgorithmMode.Kw)
        {
            if (contentEncryptionKey != null)
            {
                cek = contentEncryptionKey;
            }
            else
            {
                //TODO ensure this doesn hapenen
                //genaerate a CEK here - but this shound not happen in my codebase
            }

            var wrappedCek = ECDH.WrapCek(cek, sharedKey);
            var encryptedKey = Base64Url.Encode(wrappedCek);
            var encrypted = JweCryptoParts.Encrypt(header, clearText, cek, encryptedKey);

            return new JweCryptoParts(
                jweHeader: header,
                encryptedKey: encryptedKey,
                initializationVector: encrypted.InitializationVector,
                cipherText: encrypted.CipherText,
                authenticationTag: encrypted.AuthenticationTag
            );
        }
        else
        {
            throw new NotImplementedException();
        }

        return null;
    }


    public static JweCryptoParts EncryptMulti(JweHeader header, List<(UnprotectedHeader, byte[])> sharedSecrets, byte[] payload)
    {
        //ATTENTION: Similar to the ECDH1PU Encrypt Multi, but not identical


        var algMode = ECDH.ResolveAlgorithmMode(header.GetHeaderAlgorithm());
        var encMode = header.GetHeaderEncryption();
        // var encMode = (string)header["enc"]; // should be A256CBC-HS512
        var cek = CommonCrypto.GenerateCek(encMode.ToString());

        JweCryptoParts parts = null;
        var recipients = new List<JweRecipientCustom>();
        var isEncrypted = false;
        foreach (var sharedSecret in sharedSecrets)
        {
            string? encryptedKey = null;
            if (!isEncrypted)
            {
                parts = EncryptWithZ(header, sharedSecret.Item2, payload, cek);
                encryptedKey = parts.EncryptedKey;
                isEncrypted = true;
            }
            else if (algMode == AlgorithmMode.Kw)
            {
                var sharedKey = ECDH.DeriveSharedKey(header, sharedSecret.Item2);
                var wrappedCek = ECDH.WrapCek(cek, sharedKey);
                encryptedKey = Base64Url.Encode(wrappedCek);
            }
            else
            {
                //nothing to do here?
            }

            if (!string.IsNullOrEmpty(encryptedKey))
            {
                recipients.Add(new JweRecipientCustom(sharedSecret.Item1._unprotectedHeader, encryptedKey));
            }
        }

        if (parts is null)
        {
            throw new Exception();
        }

        return new JweCryptoParts(
            jweHeader: parts.JweHeader,
            recipients: recipients, //TODO in Kotlin this is a unmodifiableList??
            initializationVector: parts.InitializationVector,
            cipherText: parts.CipherText,
            authenticationTag: parts.AuthenticationTag);
    }

    public static Byte[] ComputeECSharedSecret(Jwk publicKey, Byte[] PrivateKeyIn)
    {
        ECPoint publicKeyQ = null;
        ECPrivateKeyParameters privateKeyX = null;
        ECCurve curve = null;
        ECPoint g = null;
        BigInteger n = null;
        publicKeyQ = ECUtils.GeneratePublicKeyByteArray(publicKey);

        if (publicKey.Crv == "P-256")
        {
            X9ECParameters ecParams = SecNamedCurves.GetByName("secp256r1");
            curve = ecParams.Curve;
            g = ecParams.G;
            n = ecParams.N;
            BigInteger d = new BigInteger(1,PrivateKeyIn);
            privateKeyX = new ECPrivateKeyParameters(d, new ECDomainParameters(curve, g, n));
        }
        else if (publicKey.Crv == "P-384")
        {
            X9ECParameters ecParams = SecNamedCurves.GetByName("secp384r1");
            curve = ecParams.Curve;
            g = ecParams.G;
            n = ecParams.N;
            BigInteger d = new BigInteger(1,PrivateKeyIn);
            privateKeyX = new ECPrivateKeyParameters(d, new ECDomainParameters(curve, g, n));
        }
        else if (publicKey.Crv == "P-521")
        {
            X9ECParameters ecParams = SecNamedCurves.GetByName("secp521r1");
            curve = ecParams.Curve;
            g = ecParams.G;
            n = ecParams.N;
            BigInteger d = new BigInteger(1,PrivateKeyIn);
            privateKeyX = new ECPrivateKeyParameters(d, new ECDomainParameters(curve, g, n));
        }


        var agreement = new ECDHCBasicAgreement();
        agreement.Init(privateKeyX);
        var secret = agreement.CalculateAgreement(new ECPublicKeyParameters(publicKeyQ, new ECDomainParameters(curve, g, n)));


        return FixPadding(secret.ToByteArray());
    }

    // Very simple implementation of RFC 8422
    // [..]    P-256 this means that each of X and Y use 32 octets, padded on the
    // left by zeros if necessary.  For P-384, they take 48 octets each, and
    // for P-521, they take 66 octets each. 
    public static byte[] FixPadding(byte[] array)
    {
        if (array[0] == 0 && (array.Length == 33 || array.Length == 49 || array.Length == 67))
        {
            return array.Skip(1).ToArray();
        }
        else if (array.Length == 31 || array.Length == 47 || array.Length == 65)
        {
            var paddedArray = new byte[array.Length + 1];
            Array.Copy(array, 0, paddedArray, 1, array.Length);
            return paddedArray;
        }

        return array;
    }
}