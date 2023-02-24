namespace Blocktrust.DIDComm.Secrets;

using Blocktrust.Common.Models.Secrets;
using Blocktrust.Common.Resolver;

public class SecretResolverInMemory : ISecretResolver
{
    private Dictionary<string, Secret> secrets;

    public SecretResolverInMemory(List<Secret> docs) : this(docs.ToDictionary(it => it.Kid, it => it))
    {
    }

    public SecretResolverInMemory(Dictionary<string, Secret> secrets)
    {
        this.secrets = secrets;
    }
    
    public SecretResolverInMemory()
    {
        this.secrets = new Dictionary<string, Secret>();
    }

    public Secret? FindKey(string kid) =>
        secrets.ContainsKey(kid) ? secrets[kid] : null;

    public HashSet<string> FindKeys(List<string> kids) =>
        kids.Intersect(this.secrets.Keys).ToHashSet();

    public void AddKey(string kid,Secret secret)
    {
        secrets.Add(kid, secret);
    }
}