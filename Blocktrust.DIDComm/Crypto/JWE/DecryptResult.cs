namespace Blocktrust.DIDComm.Crypto.JWE;

public class DecryptResult
{
    public Dictionary<string, object> UnpackedMessage { get; set; }
    public List<string> ToKids { get; set; }
    public string FromKid { get; set; } = null; 
    
    public DecryptResult(Dictionary<string, object> unpackedMessage, List<string> toKids, string fromKid = null)
    {
        UnpackedMessage = unpackedMessage;
        ToKids = toKids;
        FromKid = fromKid;
    }
}