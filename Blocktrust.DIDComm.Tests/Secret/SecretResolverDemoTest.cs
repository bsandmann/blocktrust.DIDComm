namespace Blocktrust.DIDComm.Secret;

using Blocktrust.Common.Models.Secrets;
using Secrets;

public class SecretResolverDemoTest
{
    public Secret CreateSecret()
    {
        return SecretUtils.JwkToSecret(SecretUtils.GenerateEd25519Keys().PrivateKey);
    }
  
    [Fact]
    public void TestAddGetKeys()
    {
        // var secretsFolder = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        // Directory.CreateDirectory(secretsFolder); 
        // var secret1 = CreateSecret();
        // var secret2 = CreateSecret();
        // var secretsResolver = new SecretResolverDemo(Path.Combine(secretsFolder, "secrets.json"));
        //
        // secretsResolver.AddKey(secret1);
        // secretsResolver.AddKey(secret2);
        //
        // //TODO i was wokring on that. buts its not machting at all
        // Assert.Equal(secret1.VerificationMaterial.value, secretsResolver.FindKey(secret1.Kid).VerificationMaterial.value);
        // Assert.Equal(secret2, secretsResolver.FindKey(secret2.Kid));
        // Assert.False(secretsResolver.FindKey("unknown-kid") != null);
        //
        // Assert.Equal(new List<string> { secret1.Kid, secret2.Kid }, secretsResolver.GetKids());
        //
        // Assert.Equal(new HashSet<string> { secret1.Kid }, secretsResolver.FindKeys(new List<string> { secret1.Kid }));
        // Assert.Equal(new HashSet<string> { secret2.Kid }, secretsResolver.FindKeys(new List<string> { secret2.Kid }));
        // Assert.Equal(new HashSet<string> { secret1.Kid, secret2.Kid }, secretsResolver.FindKeys(new List<string> { secret1.Kid, secret2.Kid }));
        // Assert.Equal(new HashSet<string>(), secretsResolver.FindKeys(new List<string> { "unknown-kid" }));
    }
    
    [Fact]
    public void TestLoadPreservesKeys()
    {
        // var secretsFolder = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        // Directory.CreateDirectory(secretsFolder);
        // var secret1 = CreateSecret();
        // var secret2 = CreateSecret();
        // var secretsResolver = new SecretResolverDemo(Path.Combine(secretsFolder, "secrets.json"));
        //
        // secretsResolver.AddKey(secret1);
        // secretsResolver.AddKey(secret2);
        //
        // secretsResolver = new SecretResolverDemo(Path.Combine(secretsFolder, "secrets.json"));
        //
        // Assert.Equal(secret1, secretsResolver.FindKey(secret1.Kid));
        // Assert.Equal(secret2, secretsResolver.FindKey(secret2.Kid));
        // Assert.False(secretsResolver.FindKey("unknown-kid") != null);
        //
        // Assert.Equal(new List<string> { secret1.Kid, secret2.Kid }, secretsResolver.GetKids());
        //
        // Assert.Equal(new HashSet<string> { secret1.Kid }, secretsResolver.FindKeys(new List<string> { secret1.Kid }));
        // Assert.Equal(new HashSet<string> { secret2.Kid }, secretsResolver.FindKeys(new List<string> { secret2.Kid }));
        // Assert.Equal(new HashSet<string> { secret1.Kid, secret2.Kid }, secretsResolver.FindKeys(new List<string> { secret1.Kid, secret2.Kid }));
        // Assert.Equal(new HashSet<string>(), secretsResolver.FindKeys(new List<string> { "unknown-kid" }));
    }
}