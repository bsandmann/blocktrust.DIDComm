namespace Blocktrust.DIDComm.Crypto.JWE;

public class EncryptResult
{
    public string PackedMessage { get; set; }
    public List<string> ToKids { get; set; }
    public string FromKid { get; set; } = null; 
    
    public EncryptResult(string packedMessage, List<string> toKids, string fromKid = null)
    {
        PackedMessage = packedMessage;
        ToKids = toKids;
        FromKid = fromKid;
    }
}