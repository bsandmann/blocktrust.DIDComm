namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using Org.BouncyCastle.Security;

public static class CommonCrypto
{
    public static byte[] GenerateCek(string encMode)
    {
        //check for allowed algorighms
        //and also get the bitlength
        var length = EncryptionMethod.GetEncryptionLength(encMode);

        var encBitLength = length;
        byte[] cekMaterial = new byte[(encBitLength + 7) / 8];
        var random = new SecureRandom();
        cekMaterial = random.GenerateSeed(cekMaterial.Length);

        return cekMaterial;
    }

    //TODO I hate this desgin choise of trowing exceoptions
    public static void CheckCekLength(byte[] cek, string getHeaderEncryption)
    {
        var lengh = EncryptionMethod.GetEncryptionLength(getHeaderEncryption);
        if (cek.LongLength * 8 != lengh)
        {
            //TODO possibel overflow ? even with long length?
            throw new Exception("The Content Encryption Key (CEK) length for " + getHeaderEncryption + " must be " + EncryptionMethod.GetEncryptionLength(getHeaderEncryption) + " bits");
        }
    }

    //FOR ECDH
    public static byte[] DeriveSharedSecret(Jwk epk, byte[] privateKey)
    {
        //TODO some checks here


        byte[] sharedSecretBytes;
        try
        {
            if (epk.Kty == "EC")
            {
                sharedSecretBytes = ECDH.ComputeECSharedSecret(epk, privateKey);
            }
            else
            {
                var publicKeyBytes = Base64Url.Decode(epk.X);
                sharedSecretBytes = ECDH1PU.ComputeX25519SharedSecret(publicKeyBytes, privateKey);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }

        return sharedSecretBytes;
    }

    //TODO In Kotlin this is in ContentCryptoProvider. Which is a bit better than commoncrypto. Need a better place
    public static byte[] Decrypt(JweHeader header, string iv, string cipherText, string authTag, byte[] cek)
    {
        CheckCekLength(cek, header.GetHeaderEncryption());
        byte[] aad = ECDH.ComputeAAD(header);
        var headerEncryptionMethod = header.GetHeaderEncryption();
        byte[] plaintext;
        if (headerEncryptionMethod.Equals(EncryptionMethod.A256CBC_HS512))
        {
            plaintext = AESCBCEncryptor.DecryptAuthenticated(cek, Base64Url.Decode(iv), Base64Url.Decode(cipherText), aad, Base64Url.Decode(authTag));
            return plaintext;
        }
        else if (headerEncryptionMethod.Equals(EncryptionMethod.A256GCM))
        {
            plaintext = AESGCMEncryptor.Decrypt(cek, Base64Url.Decode(iv), Base64Url.Decode(cipherText), aad, Base64Url.Decode(authTag));
            return plaintext;
        }
        else if (headerEncryptionMethod.Equals(EncryptionMethod.XC20P))
        {
            var combinedCiphertextAndAuthTag = Base64Url.Decode(cipherText).Concat(Base64Url.Decode(authTag)).ToArray();
            plaintext = XChaCha20Poly1305.Decrypt(cek, Base64Url.Decode(iv), combinedCiphertextAndAuthTag, aad);
            return plaintext;
        }
        else
        {
            throw new NotImplementedException();
        }

        return null;
    }
}