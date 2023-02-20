namespace Blocktrust.DIDComm.Tests.TestData.Mock;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Secrets;

public class CharlieSecretResolverMock : SecretResolverInMemoryMock
{
    private static List<Secret> secrets = new List<Secret>()
    {
        new Secret(
            kid:  "did:example:charlie#key-x25519-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial()
            {
                format = VerificationMaterialFormat.Jwk,
                value =  """
                        {
                           "kty":"OKP",
                           "d":"Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                           "crv":"X25519",
                           "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                        }
                """
            }
        ),
        new Secret(
            kid: "did:example:charlie#key-x25519-3",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial()
            {
                format = VerificationMaterialFormat.Jwk,
                value =    """
                        {
                           "kty":"OKP",
                           "d":"Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                           "crv":"X25519",
                           "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                        }
                """
            }
        ),
    };
        
    private SecretResolverInMemory _secretResolverInMemory = new SecretResolverInMemory(secrets);

    public List<Secret> GetSecrets()
    {
        return secrets;
    }

    public List<String> GetSecretKids()
    {
        return secrets.Select(secret => secret.Kid).ToList();
    }

    public Secret? FindKey(String kid)
    {
        return _secretResolverInMemory.FindKey(kid);
    }

    public HashSet<String> FindKeys(List<String> kids)
    {
        return _secretResolverInMemory.FindKeys(kids);
    }
}