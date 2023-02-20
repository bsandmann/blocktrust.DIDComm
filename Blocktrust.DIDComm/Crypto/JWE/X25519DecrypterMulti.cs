namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using JWM;

public class X25519DecrypterMulti  :IJWEDecrypterMulti
{
    public X25519DecrypterMulti(List<(UnprotectedHeader, Jwk)> recipients)
    {
        this.Recipients = recipients;
    }

    public List<(UnprotectedHeader, Jwk)> Recipients { get; }
    
    public byte[] DecryptPayload(JweHeader unprotectedHeader, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        //TODO the header has be to checked here. Also has to implemented in the other decryption classes
        //TODO the ephemeral Public Key is loaded here. What kind of class ist that? JWKCustom?
        //The transformation is also bullshit
        var ephemeralPublicKey = (Jwk)unprotectedHeader.Header["epk"];

        //TODO throw if publickey is not present. 
        //TODO some of the stuff here iy identitcal to the encryption part of thing. dry
        var sharedKeys = new List<(Dictionary<string, object> kid, byte[] sharedSecrets)>();
        
        foreach (var recipient in this.Recipients)
        {
            //TODO check is the curve of the public key does macht the curse of the private key
            
            
            var sharedKeyZ = CommonCrypto.DeriveSharedSecret(ephemeralPublicKey, privateKey: Base64Url.Decode(recipient.Item2.D));
            
            var kid = recipient.Item1._unprotectedHeader;
            sharedKeys.Add((kid, sharedKeyZ));
        }
        var decryptedPayload = DecryptMulti(unprotectedHeader, sharedKeys, recipients, iv, cipherText, authTag);
        return decryptedPayload;
    }

    private byte[] DecryptMulti(JweHeader unprotectedHeader, List<(Dictionary<string, object> kid, byte[] sharedSecrets)> sharedKeys, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        //Identical code to ECDH1PUx25519
        
        byte[] result = new byte[] { };
        string encryptedKey = null;

        foreach (var sharedKey in sharedKeys)
        {
            var kidSharedKey = (string)sharedKey.kid["kid"];
            foreach (var recipient in recipients)
            {
                if (kidSharedKey.Equals(recipient.UnprotectedHeader["kid"]))
                {
                    encryptedKey = recipient.EncryptedKey;
                }
            }

            result = DecryptWithZ(unprotectedHeader, sharedKey.sharedSecrets, encryptedKey, iv, cipherText, authTag);
        }

        return result;
    }

    private byte[] DecryptWithZ(JweHeader header, byte[] z, string? encryptedKey, string iv, string cipherText, string authTag)
    {
        var alg = header.GetHeaderAlgorithm();
        var algMode = ECDH.ResolveAlgorithmMode(alg);
        byte[] cek;
        
        var sharedKey = ECDH.DeriveSharedKey(header, z);
        
        if (algMode == AlgorithmMode.Direct)
        {
            throw new NotImplementedException();
            //Get name??
            cek = sharedKey;
        }
        else if (algMode == AlgorithmMode.Kw)
        {
            if (encryptedKey is null)
            {
                throw new Exception();
            }
            var authTagString = authTag; 
            var decodedEncryptionKey = Base64Url.Decode(encryptedKey);
            cek = JweObject.UnwrapCek(sharedKey, decodedEncryptionKey);
        }
        else
        {
            throw new Exception();
        }

        var decryptionResult = CommonCrypto.Decrypt(header, iv, cipherText, authTag, cek);
        return decryptionResult;
    }

  
}