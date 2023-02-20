namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using JWM;

public class ECDHDecrypterMulti: IJWEDecrypterMulti
{
    public ECDHDecrypterMulti(List<(UnprotectedHeader, Jwk)> recipients)
    {
        this.Recipients = recipients;
    }

    public List<(UnprotectedHeader, Jwk)> Recipients { get; }
    public byte[] DecryptPayload(JweHeader unprotectedHeader, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        //TODO some header check here
        var ephemeralPublicKey = (Jwk)unprotectedHeader.Header["epk"];
        
        //TODO throw if publickey is not present. 
        
        var sharedKeys = new List<(Dictionary<string, object> kid, byte[] sharedSecrets)>();
        
        foreach (var recipient in this.Recipients)
        {
            
            //TODO check hat point is on curve
            
            var sharedKeyZ = CommonCrypto.DeriveSharedSecret(ephemeralPublicKey, Base64Url.Decode(recipient.Item2.D));
            sharedKeys.Add((recipient.Item1._unprotectedHeader, sharedKeyZ));
        }
        
        var decryptedPayload = DecryptMulti(unprotectedHeader, sharedKeys, recipients, iv, cipherText, authTag);
        return decryptedPayload;
    }
    
    private byte[] DecryptMulti(JweHeader unprotectedHeader, List<(Dictionary<string, object> kid, byte[] sharedSecrets)> sharedKeys, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        //Identical code to x25519
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
            var authTagString = authTag; // Base64Url.Encode(authTag);
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