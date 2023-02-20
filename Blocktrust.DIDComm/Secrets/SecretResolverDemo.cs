namespace Blocktrust.DIDComm.Secrets;

using System.Text.Json;
using Blocktrust.Common.Converter;
using Blocktrust.Common.Models.Secrets;
using Crypto.JWE;

public class SecretResolverDemo : SecretResolverEditable
{
    private readonly string _filePath;
    private readonly Dictionary<string, Secret> _secrets;

    public SecretResolverDemo(string filePath = "secrets.json")
    {
        _filePath = filePath;

        if (!File.Exists(_filePath))
        {
            _secrets = new Dictionary<string, Secret>();
            Save();
        }
        else
        {
            var secretsJson = File.ReadAllText(_filePath);

            if (!string.IsNullOrEmpty(secretsJson))
            {
                var secretsList = JsonSerializer.Deserialize<List<Jwk>>(secretsJson);
                var list = secretsList.Select(p =>
                {
                    //TODO to late to think straight. It is most likely false
                    var dic = p.ToDictionary()
                        .ToDictionary((p => p.Key), (p => p.Value));
                    return SecretUtils.JwkToSecret(dic);
                });
            }
            else
            {
                _secrets = new Dictionary<string, Secret>();
            }
        }
    }

    private void Save()
    {
        var secretJson = JsonSerializer.Serialize(_secrets.Values.Select(SecretUtils.SecretToJwk),SerializationOptions.UnsafeRelaxedEscaping);
        File.WriteAllText(_filePath, secretJson);
    }

    public void AddKey(Secret secret)
    {
        _secrets[secret.Kid] = secret;
        Save();
    }

    public IEnumerable<string> GetKids()
    {
        return _secrets.Keys;
    }

    public Secret? FindKey(string kid)
    {
        return _secrets.ContainsKey(kid) ? _secrets[kid] : null;
    }

    public ISet<string> FindKeys(IEnumerable<string> kids)
    {
        return new HashSet<string>(kids.Intersect(_secrets.Keys));
    }
}