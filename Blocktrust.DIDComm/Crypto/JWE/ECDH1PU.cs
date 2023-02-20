namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using Blocktrust.Common.Converter;
using Exceptions;
using JWM;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

public static class ECDH1PU
{
    public static byte[] DeriveSenderZ(byte[] privateKeyOfSender, byte[] publicKeyOfRecipient, byte[] epk)
    {
        //TODO validate that they are on the same curve

        var Ze = ComputeX25519SharedSecret(publicKeyOfRecipient, epk);
        var Zs = ComputeX25519SharedSecret(publicKeyOfRecipient, privateKeyOfSender);
        var Z = Ze.Concat(Zs).ToArray();
        return Z;
    }

    /// <summary>
    /// Gets the shared secret.
    /// </summary>
    /// <param name="PublicKeyIn">The public key in.</param>
    /// <param name="PrivateKeyIn">The private key in.</param>
    /// <returns>Byte[].</returns>
    public static Byte[] ComputeX25519SharedSecret(Byte[] PublicKeyIn, Byte[] PrivateKeyIn)
    {
        X25519Agreement agreement = new X25519Agreement();
        var privKey = new X25519PrivateKeyParameters(PrivateKeyIn);
        var pubKey = new X25519PublicKeyParameters(PublicKeyIn);

        agreement.Init(privKey);
        byte[] secret = new byte[32];
        agreement.CalculateAgreement(pubKey, secret, 0);

        return secret;
    }


    public static AlgorithmMode ResolveAlgorithmMode(string alg)
    {
        //ATTENTION Simimlar code also in ECDH1PU

        if (alg == JweAlgorithmExtension.ECDH_1PU_A256KW)
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

    public static byte[] DeriveSharedKey(JweHeader header, byte[] sharedKeyZ, string encryptedAuthenticationTag)
    {
        //TODO
        //Some checks for stuff not being null

        var sharedKeyLength = 256; //just a assumption TODO check
        string algIdString;
        var algMode = ECDH1PU.ResolveAlgorithmMode(header.GetHeaderAlgorithm());
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
        var tag = ECDH.EncodeDataWithLength(encryptedAuthenticationTag);

        var iv = algId.Concat(partyUInfo).Concat(partyVInfo).Concat(suppPubInfo).Concat(suppPrivInfo).Concat(tag).ToArray();

        //I have to use 3 things
        //z and iv and the keylength of 256

        var concatKDF = new ConcatenationKdfGenerator(new Sha256Digest());
        concatKDF.Init(new KdfParameters(sharedKeyZ, iv));
        byte[] result = new byte[32];
        concatKDF.GenerateBytes(result,0,32);
        return result;
    }


    private static JweCryptoParts EncryptWithZ(JweHeader header, byte[] sharedKeyZ, byte[] clearText, byte[] contentEncryptionKey)
    {
        //ATTENTION simimlar but not identical code in ECDH1

        //TODO we should use the Header object here and not just the dictionary
        // var agl = (string)header["alg"];
        var alg = header.GetHeaderAlgorithm();
        var algMode = ECDH1PU.ResolveAlgorithmMode(alg);
        var enc = header.GetHeaderEncryption();

        byte[] cek = new byte[] { };

        if (algMode == AlgorithmMode.Direct)
        {
            throw new NotImplementedException();
            return null;
        }
        else if (algMode == AlgorithmMode.Kw)
        {
            //TODO some checks i dont get in the kotlin code
            if (contentEncryptionKey != null)
            {
                cek = contentEncryptionKey;
            }
            else
            {
                //TODO ensure this doesn hapenen
                //genaerate a CEK here - but this shound not happen in my codebase
            }

            //TODO apply compression?
            //TODO compute AAD ???


            var encrypted = JweCryptoParts.Encrypt(header, clearText, cek);
            var sharedKey = ECDH1PU.DeriveSharedKey(header, sharedKeyZ, encrypted.AuthenticationTag);
            var wrappedCek = ECDH.WrapCek(cek, sharedKey);
            var encryptedKey = Base64Url.Encode(wrappedCek);

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
    }

    public static JweCryptoParts EncryptMulti(JweHeader header, List<(UnprotectedHeader, byte[])> sharedSecrets, byte[] payload)
    {
        //ATTENTION: Similar to the ECDH Encrypt Multi, but not identical

        var algMode = ECDH1PU.ResolveAlgorithmMode(header.GetHeaderAlgorithm());
        var encMode = header.GetHeaderEncryption();
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
                var sharedKey = ECDH1PU.DeriveSharedKey(header, sharedSecret.Item2, parts.AuthenticationTag);
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

    public static byte[] DeriveRecipientZ(Jwk privateKey, Jwk publicKey, Jwk ephemeralPublicKey)
    {
        //TODO validate they are on the same curve... see kotlin code

        var Ze = CommonCrypto.DeriveSharedSecret(ephemeralPublicKey, Base64Url.Decode(privateKey.D));
        var Zs = CommonCrypto.DeriveSharedSecret(publicKey, Base64Url.Decode(privateKey.D));
        if (Ze.Length != Zs.Length)
        {
            throw new Exception();
        }

        var Z = Ze.Concat(Zs).ToArray();
        return Z;
    }
}