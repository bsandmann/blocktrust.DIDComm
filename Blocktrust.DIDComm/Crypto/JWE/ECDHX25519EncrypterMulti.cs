namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using Blocktrust.Common.Converter;
using JWM;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class ECDHX25519EncrypterMulti : IJWEEncrypterMulti
{
    public ECDHX25519EncrypterMulti(List<(UnprotectedHeader, Jwk)> recipient)
    {
        this.Recipients = recipient;
    }

    public List<(UnprotectedHeader, Jwk)> Recipients { get; }

    public JweCryptoParts Encrypt(JweHeader header, JwePayload Payload)
    {
        //ATTENTION: this code ist quite simialr to the ECDH1PuX25519 Encryptor Multi. 
        //But not exactly

        var payload = Encoding.UTF8.GetBytes(Payload.JsonString);

        // generate public and private key
        var keyGenerator = new X25519KeyPairGenerator();
        keyGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var keys = keyGenerator.GenerateKeyPair();


        var publicKey = (X25519PublicKeyParameters)keys.Public;
        var privateKey = (X25519PrivateKeyParameters)keys.Private;

        // Update the header
        //Shitty way of building the header
        var x = publicKey.GetEncoded();
        var njwk = new Jwk();
        njwk.Kty = "OKP";
        njwk.Crv = "X25519";
        njwk.X = Base64Url.Encode(x);
        header.Epk(njwk);
        //why doensit it come from the recipeints of the jwe-object?

        var sharedKeys = new List<(UnprotectedHeader, Byte[])>();
        foreach (var recipient in Recipients)
        {
            //ALSO not very nice way of building the JWK
            var epk = new Jwk();

            var z = CommonCrypto.DeriveSharedSecret(recipient.Item2, privateKey.GetEncoded());
            sharedKeys.Add((recipient.Item1, z));
        }

        var r = ECDH.EncryptMulti(header, sharedKeys, payload);
        return r;
    }
}