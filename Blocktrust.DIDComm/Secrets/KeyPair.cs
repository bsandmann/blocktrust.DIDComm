namespace Blocktrust.DIDComm.Secrets;

public class KeyPair
{
    public readonly Dictionary<string, object> PrivateKey;
    public readonly Dictionary<string, object> PublicKey;

    public KeyPair(Dictionary<string, object> privateKey, Dictionary<string, object> publicKey)
    {
        this.PrivateKey = privateKey;
        this.PublicKey = publicKey;
    }
}