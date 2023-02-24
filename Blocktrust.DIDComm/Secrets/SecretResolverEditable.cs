namespace Blocktrust.DIDComm.Secrets;

using Blocktrust.Common.Models.Secrets;
using Blocktrust.Common.Resolver;

public class SecretResolverEditable : ISecretResolver
{
    void AddKey(Secret secret)
    {
        throw new NotImplementedException();
    }

    IEnumerable<string> GetKids()
    {
        throw new NotImplementedException();
    }

    public Secret? FindKey(string kid)
    {
        throw new NotImplementedException();
    }

    public HashSet<string> FindKeys(List<string> kids)
    {
        throw new NotImplementedException();
    }

    public void AddKey(string kid, Secret secret)
    {
        throw new NotImplementedException();
    }
}