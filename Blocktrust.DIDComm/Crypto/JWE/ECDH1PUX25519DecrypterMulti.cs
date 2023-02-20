namespace Blocktrust.DIDComm.Crypto.JWE;

using Blocktrust.Common.Converter;
using JWM;

public class ECDH1PUX25519DecrypterMulti : IJWEDecrypterMulti
{
    public ECDH1PUX25519DecrypterMulti(Jwk sender, List<(UnprotectedHeader, Jwk)> recipients)
    {
        this.Sender = sender;
        this.Recipients = recipients;
    }

    public Jwk Sender { get; }
    public List<(UnprotectedHeader, Jwk)> Recipients { get; }

    //TODO first: i should pass a JWEHeader object here and not just a dictionary
    //Second the Payload decrpytor might have to move into the deticated classes ECD1PUX255... Multi etc.
    public byte[] DecryptPayload(JweHeader unprotectedHeader, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        //TODO the header has be to checked here. Also has to implemented in the other decryption classes

        //TODO the ephemeral Public Key is loaded here. What kind of class ist that? JWKCustom?
        //The transformation is also bullshit
        var ephemeralPublicKey = (Jwk)unprotectedHeader.Header["epk"];
        // var epkFromDictionary = unprotectedHeader.Header[];
        // ephemeralPublicKey.Kty = (string)epkFromDictionary["kty"];
        // ephemeralPublicKey.X = (string)epkFromDictionary["x"];
        // ephemeralPublicKey.Crv = (string)epkFromDictionary["crv"];

        // var epk = epkFromDictionary.EnumerateObject();

        //TODO throw if publickey is not present. 

        //TODO some of the stuff here iy identitcal to the encryption part of thing. dry
        var sharedKeys = new List<(Dictionary<string, object> kid, byte[] sharedSecrets)>();
        foreach (var recipient in this.Recipients)
        {
            var sharedKeyZ = ECDH1PU.DeriveRecipientZ(recipient.Item2, this.Sender, ephemeralPublicKey);
            //TODO murks
            var kid = recipient.Item1._unprotectedHeader;
            sharedKeys.Add((kid, sharedKeyZ));
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
            var authTagString = authTag; // Base64Url.Encode(authTag);

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