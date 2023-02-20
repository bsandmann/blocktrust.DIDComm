namespace Blocktrust.DIDComm.Crypto.JWE;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class AESGCMEncryptor
{
    
    private const string Algorithm = "AES";
    private const string CipherMode = "GCM";
    private const string _algorithm = $"{Algorithm}/{CipherMode}/NoPadding";
    public static byte[] Decrypt(byte[] cek, byte[] iv, byte[] cipherText, byte[] aad, byte[] authTag)
    {
        var cipherTextAndAuthTag = cipherText.Concat(authTag).ToArray();

        var cipher = CipherUtilities.GetCipher(_algorithm);
        var parameters = new AeadParameters(new KeyParameter(cek), authTag.Length * 8, iv,aad);
        cipher.Init(false, parameters);
        var plaintextBytes = new byte[cipherText.Length];
        var offset = cipher.ProcessBytes(cipherTextAndAuthTag, 0, cipherTextAndAuthTag.Length, plaintextBytes, 0);
        // cipher.
        cipher.DoFinal(plaintextBytes, offset); // authenticate data via tag

        return plaintextBytes;
    }
    
    
    public AuthenticatedCipherText Encrypt(byte[] plainText, byte[] cek, byte[] aad, byte[] iv){
        
        const int tagLenth = 16; // in bytes
        var nonce = iv;

        var plaintextBytes = plainText;
        var bcCiphertext = new byte[plaintextBytes.Length + tagLenth];
    
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(cek), tagLenth * 8, nonce, aad);
        cipher.Init(true, parameters);
    
        var offset = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, bcCiphertext, 0);
        cipher.DoFinal(bcCiphertext, offset);

        // Bouncy Castle includes the authentication tag in the ciphertext
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[tagLenth];
        Buffer.BlockCopy(bcCiphertext, 0, ciphertext, 0, plaintextBytes.Length);
        Buffer.BlockCopy(bcCiphertext, plaintextBytes.Length, tag, 0, tagLenth);


        return new AuthenticatedCipherText()
        {
            CipherText = ciphertext,
            AuthenticationTag = tag
        };
    }
    
}