namespace Blocktrust.DIDComm.Secrets;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Utils;

public class SecretUtils
{
    public static Secret JwkToSecret(Dictionary<string, object> jwk)
    {
        return new Secret(
            kid: jwk["kid"]?.ToString() ?? "",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial(
                VerificationMaterialFormat.Jwk,
                jwk.ToJsonString())
        );
    }

    public static Dictionary<string, object> SecretToJwk(Secret secret)
    {
        return JsonSerializer.Deserialize<Dictionary<string, object>>(secret.VerificationMaterial.value);
    }


    public static KeyPair GenerateEd25519Keys()
    {
        //TODO very unelegant. There must be a better way to automatically gererate a keypair
        //maybe I already do this somehwere in the code?

        var keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = keyPairGenerator.GenerateKeyPair();
        var privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;
        var publicKeyFromPrivate = privateKey.GeneratePublicKey();
        var publicKey = (Ed25519PublicKeyParameters)keyPair.Public;

        var privateKeyDictionary = new Dictionary<string, object>();
        var publicKeyDictionary = new Dictionary<string, object>();
        //TODO a lot of optimization potential here
        privateKeyDictionary.Add("crv", "Ed25519");
        publicKeyDictionary.Add("crv", "Ed25519");
        privateKeyDictionary.Add("kty", "OKP");
        publicKeyDictionary.Add("kty", "OKP");
        privateKeyDictionary.Add("d", Base64Url.Encode(privateKey.GetEncoded()));
        privateKeyDictionary.Add("x", Base64Url.Encode(publicKeyFromPrivate.GetEncoded()));
        publicKeyDictionary.Add("x", Base64Url.Encode(publicKey.GetEncoded()));
        var kid = KeyIdFromSha256Thumbprint("Ed25519", Base64Url.Encode(publicKey.GetEncoded()), "OKP");
        privateKeyDictionary.Add("kid", kid);
        publicKeyDictionary.Add("kid", kid);
        return new KeyPair(privateKeyDictionary, publicKeyDictionary);
    }

    public static KeyPair GenerateX25519Keys()
    {

        var keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = keyPairGenerator.GenerateKeyPair();
        var privateKey = (X25519PrivateKeyParameters)keyPair.Private;
        var publicKeyFromPrivate = privateKey.GeneratePublicKey();
        var publicKey = (X25519PublicKeyParameters)keyPair.Public;

        var privateKeyDictionary = new Dictionary<string, object>();
        var publicKeyDictionary = new Dictionary<string, object>();
        //TODO a lot of optimization potential here
        privateKeyDictionary.Add("crv", "X25519");
        publicKeyDictionary.Add("crv", "X25519");
        privateKeyDictionary.Add("kty", "OKP");
        publicKeyDictionary.Add("kty", "OKP");
        privateKeyDictionary.Add("d", Base64Url.Encode(privateKey.GetEncoded()));
        privateKeyDictionary.Add("x", Base64Url.Encode(publicKeyFromPrivate.GetEncoded()));
        publicKeyDictionary.Add("x", Base64Url.Encode(publicKey.GetEncoded()));
        var kid = KeyIdFromSha256Thumbprint("X25519", Base64Url.Encode(publicKey.GetEncoded()), "OKP");
        privateKeyDictionary.Add("kid", kid);
        publicKeyDictionary.Add("kid", kid);
        return new KeyPair(privateKeyDictionary, publicKeyDictionary);
    }

    private static string KeyIdFromSha256Thumbprint(string crv, string x, string kty)
    {
        x = "F9KF2ZRcfBbJfiZFsDZvkqwU23eo4cVeeF-XUhSOZAQ";
        
        // Put mandatory params in sorted order
        var requiredParams = new SortedDictionary<string, string>();
        requiredParams.Add("crv", crv);
        requiredParams.Add("kty", kty);
        requiredParams.Add("x", x);
        var serialized = JsonSerializer.Serialize(requiredParams);
        var encData = Encoding.UTF8.GetBytes(serialized);
        Org.BouncyCastle.Crypto.Digests.Sha256Digest hash = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
        hash.BlockUpdate(encData, 0, encData.Length);
        byte[] compArr = new byte[hash.GetDigestSize()];
        hash.DoFinal(compArr, 0);
        return Base64Url.Encode(compArr);
    }
}