namespace Blocktrust.DIDComm.Secret;

using Blocktrust.Common.Models.DidDoc;
using Secrets;

public class SecretUtilsTest
{
    [Fact]
    public void TestGenerateKeysEd25519()
    {
        var keys = SecretUtils.GenerateEd25519Keys();
        Assert.Equal("Ed25519", keys.PrivateKey["crv"]);
        Assert.Equal("Ed25519", keys.PublicKey["crv"]);
        Assert.Equal("OKP", keys.PrivateKey["kty"]);
        Assert.Equal("OKP", keys.PublicKey["kty"]);
        Assert.True(keys.PrivateKey.ContainsKey("x"));
        Assert.True(keys.PrivateKey.ContainsKey("d"));
        Assert.True(keys.PublicKey.ContainsKey("x"));
        Assert.False(keys.PublicKey.ContainsKey("d"));
    }

    [Fact]
    public void TestGenerateKeysX25519()
    {
        var keys = SecretUtils.GenerateX25519Keys();
        Assert.Equal("X25519", keys.PrivateKey["crv"]);
        Assert.Equal("X25519", keys.PublicKey["crv"]);
        Assert.Equal("OKP", keys.PrivateKey["kty"]);
        Assert.Equal("OKP", keys.PublicKey["kty"]);
        Assert.True(keys.PrivateKey.ContainsKey("x"));
        Assert.True(keys.PrivateKey.ContainsKey("d"));
        Assert.True(keys.PublicKey.ContainsKey("x"));
        Assert.False(keys.PublicKey.ContainsKey("d"));
    }


    [Fact]
    public void TestJwkToSecret()
    {
        var keys = SecretUtils.GenerateEd25519Keys();
        var secret = SecretUtils.JwkToSecret(keys.PrivateKey);
        Assert.Equal(VerificationMethodType.JsonWebKey2020, secret.Type);
        Assert.Equal(keys.PrivateKey["kid"], secret.Kid);
        Assert.Equal(VerificationMaterialFormat.Jwk, secret.VerificationMaterial.Format);
    }

    [Fact]
    public void TestSecretToJwk()
    {
        //TODO not the best
        var keys = SecretUtils.GenerateEd25519Keys();
        var secret = SecretUtils.JwkToSecret(keys.PrivateKey);
        var jwk = SecretUtils.SecretToJwk(secret);
        Assert.Equivalent(keys.PrivateKey["crv"], jwk["crv"].ToString());
        Assert.Equivalent(keys.PrivateKey["kty"], jwk["kty"].ToString());
        Assert.Equivalent(keys.PrivateKey["d"], jwk["d"].ToString());
        Assert.Equivalent(keys.PrivateKey["x"], jwk["x"].ToString());
    }
}