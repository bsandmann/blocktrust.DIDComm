namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using JWS;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

//TODO this is a naive custom implemenation of the JWEObjectJson found in the Kotlin-Library

public class JweObject
{
    public JweHeader ProtectedHeader { get; set; }
    public JweHeader UnprotectedHeader { get; set; }

    public List<JweRecipientCustom> Recipients { get; set; }

    //base64
    public string CipherText { get; set; }

    //Base64
    public string AuthTag { get; set; }

    //Base64
    public string Iv { get; set; }

    public string SigningInputString { get; }

    public JwePayload Payload { get; set; }

    //TODO jws is used herer
    public List<JwsSignature> Signatures { get; set; }

    //TODO jws is used herer
    public JweTokenState State { get; set; }

    public byte[] ClearText { get; set; }


    public JweObject()
    {
    }

    public JweObject(JweHeader protectedHeader, string payload)

    {
        ProtectedHeader = protectedHeader;
        // UnprotectedHeader = unprotectedHeader;
        Payload = new JwePayload(payload);
        State = JweTokenState.Unencrypted;
        Signatures = new List<JwsSignature>();
        var header = JsonSerializer.Serialize(protectedHeader, SerializationOptions.UnsafeRelaxedEscaping);
        var bytesHeader = Encoding.UTF8.GetBytes(header);
        var headerBase64 = Base64Url.Encode(bytesHeader);

        SigningInputString = $"{headerBase64}.{Payload.Base64}";
    }


    public string GetHeaderAlgorithm()
    {
        var alg = this.UnprotectedHeader.GetHeaderAlgorithm(); //JSONUtils.GetTyped<string>(UnprotectedHeader, "alg");// UnprotectedHeader["alg"].ToString();
        return alg;
        //TODO may check if the algorithm is supported
        // if (!isSuccessful)
        // {
        //     throw new UnsupportedAlgorithmException($"{UnprotectedHeader["alg"].ToString()}+{UnprotectedHeader["enc"].ToString()}");
        // }

        // return algorithm;
    }

    public string GetHeaderEncryption()
    {
        var enc = UnprotectedHeader.GetHeaderEncryption(); 
        //TODO maybe check if the algorithm is supported
        return enc;

        // var isSuccessful = JweEncryption.TryParse(enc, out JweEncryption encryption);
        // if (!isSuccessful)
        // {
        //     throw new UnsupportedAlgorithmException($"{UnprotectedHeader["alg"].ToString()}+{UnprotectedHeader["enc"].ToString()}");
        // }
        //
        // return encryption;
    }

    public JweCryptoParts Encrypt(IJWEEncrypterMulti encryptor)
    {
        //TODO it seems there asr not yet checks on the kotlin side here...
        //ensureUnencryptedState();
        //ensureJWEEncrypterSupport(encrypter); 

        var r = encryptor.Encrypt(ProtectedHeader, Payload);
        return r;
    }

    public void Decrypt(IJWEDecrypterMulti encryptor)
    {
        if (this.State != JweTokenState.Encrypted)
        {
            throw new Exception();
        }

        //the idea is that we create a new payload with is null atm

        try
        {
            //TODO we need a build / or fromDictionary to build that header
            var decryptedPayload = encryptor.DecryptPayload(UnprotectedHeader, this.Recipients, this.Iv, this.CipherText, this.AuthTag);
            var decodedPaylaod = Encoding.UTF8.GetString(decryptedPayload);
            var payload = new JwePayload(decodedPaylaod);
            this.State = JweTokenState.Decrypted;
            this.Payload = payload;
        }
        catch (Exception e)
        {
            throw new Exception("Decrypt is failed");
        }
    }


    public static byte[] UnwrapCek(byte[] kek, byte[] encryptedCek)
    {
        var wrapEngine = new AesWrapEngine();
        wrapEngine.Init(false, new KeyParameter(kek));
        var wrapped = wrapEngine.Unwrap(encryptedCek, 0, encryptedCek.Length);
        return wrapped;
    }
}