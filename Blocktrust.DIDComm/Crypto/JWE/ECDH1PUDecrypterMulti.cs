namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using JWM;

public class ECDH1PUDecrypterMulti : IJWEDecrypterMulti
{
    public ECDH1PUDecrypterMulti(Jwk sender, List<(UnprotectedHeader, Jwk)> recipients)
    {
        this.Sender = sender;
        this.Recipients = recipients;
    }

    public Jwk Sender { get; }
    public List<(UnprotectedHeader, Jwk)> Recipients { get; }

    public byte[] DecryptPayload(JweHeader unprotectedHeader, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        //TODO the header has be to checked here. Also has to implemented in the other decryption classes
        var sharedKeys = new List<(Dictionary<string, object> kid, byte[] sharedSecrets)>();
        var ephemeralPublicKey = (Jwk)unprotectedHeader.Header["epk"];

        foreach (var recipient in this.Recipients)
        {
            //TODO check hat point is on curve
            var sharedKeyZ = ECDH1PU.DeriveRecipientZ(recipient.Item2, this.Sender, ephemeralPublicKey);
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
        var algMode = ECDH1PU.ResolveAlgorithmMode(alg);
        byte[] cek;

        if (algMode == AlgorithmMode.Direct)
        {
            throw new NotImplementedException();
            //Get name??
            // algIdString = header.GetHeaderEncryption().ToString();
        }
        else if (algMode == AlgorithmMode.Kw)
        {
            var authTagString = authTag; 
            var sharedKey = ECDH1PU.DeriveSharedKey(header, z, authTagString);
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