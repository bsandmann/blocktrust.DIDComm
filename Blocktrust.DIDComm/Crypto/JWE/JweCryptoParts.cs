namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using Org.BouncyCastle.Security;

public class JweCryptoParts
{
    public JweHeader JweHeader { get; set; }

    //base64
    public string InitializationVector { get; set; }

    //base64
    public string CipherText { get; set; }

    //base64
    public string AuthenticationTag { get; set; }

    //base64
    public string EncryptedKey { get; set; }

    public List<JweRecipientCustom> Recipients { get; set; }

    public JweCryptoParts(JweHeader jweHeader, string initializationVector, string cipherText, string authenticationTag, string encryptedKey = null)
    {
        JweHeader = jweHeader;
        InitializationVector = initializationVector;
        CipherText = cipherText;
        AuthenticationTag = authenticationTag;
        EncryptedKey = encryptedKey;
    }

    public JweCryptoParts(JweHeader jweHeader, List<JweRecipientCustom> recipients, string initializationVector, string cipherText, string authenticationTag)
    {
        JweHeader = jweHeader;
        Recipients = recipients;
        InitializationVector = initializationVector;
        CipherText = cipherText;
        AuthenticationTag = authenticationTag;
    }

    public static JweCryptoParts Encrypt(JweHeader header, byte[] clearText, byte[] cek, string encryptedKey = null)
    {
        var enc = header.GetHeaderEncryption();
        //TODO Bad comparision with strings
        byte[] aad = ECDH.ComputeAAD(header);
        // AUTH Encrypt 
        if (enc == EncryptionMethod.A256CBC_HS512)
        {
            var random = new SecureRandom();
            byte aesIvSize = 16;
            var iv = random.GenerateSeed(aesIvSize);

            var aes = new AESCBCEncryptor();
            var authenticatedCipherText = aes.Encrypt(clearText, cek, aad, iv);

            JweCryptoParts encrypted = new JweCryptoParts(
                jweHeader: header,
                initializationVector: Base64Url.Encode(iv),
                cipherText: Base64Url.Encode(authenticatedCipherText.CipherText),
                authenticationTag: Base64Url.Encode(authenticatedCipherText.AuthenticationTag)
            );
            return encrypted;
        }
        else if (enc == EncryptionMethod.A256GCM)
        {
            var random = new SecureRandom();
            byte aesIvSize = 12;
            var iv = random.GenerateSeed(aesIvSize);

            var aes = new AESGCMEncryptor();
            var authenticatedCipherText = aes.Encrypt(clearText, cek, aad, iv);

            JweCryptoParts encrypted = new JweCryptoParts(
                jweHeader: header,
                initializationVector: Base64Url.Encode(iv),
                cipherText: Base64Url.Encode(authenticatedCipherText.CipherText),
                authenticationTag: Base64Url.Encode(authenticatedCipherText.AuthenticationTag)
            );
            return encrypted;
        }
        //ANON Encrypt
        else if (enc == EncryptionMethod.XC20P)
        {
            //TODO singleton? for secureRandom
            var secureRandom = new SecureRandom();
            var iv = secureRandom.GenerateSeed(24);
            var (ciphertext, authTag) = XChaCha20Poly1305.Encrypt(cek, iv, clearText, aad);

            JweCryptoParts encrypted = new JweCryptoParts(
                jweHeader: header,
                initializationVector: Base64Url.Encode(iv),
                cipherText: Base64Url.Encode(ciphertext),
                authenticationTag: Base64Url.Encode(authTag)
            );
            return encrypted;
        }
        else
        {
            throw new NotImplementedException();
        }
    }
}