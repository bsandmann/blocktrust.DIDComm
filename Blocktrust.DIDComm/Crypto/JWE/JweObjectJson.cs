namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text.Json.Serialization;

public class JweObjectJson
{
    //required for Serialization
    public JweObjectJson()
    {
        
    }
    
    [JsonPropertyName("ciphertext")] public string CipherText { get; set; }
    [JsonPropertyName("protected")] public string Header { get; set; }
    [JsonPropertyName("recipients")] public List<JweRecipientCustom> Recipients { get; set; }
    [JsonPropertyName("tag")] public string AuthTag { get; set; }
    // Attention! having this PropertyName causes a exception in rider
    // [JsonPropertyName("iv")] 
    public string Iv { get; set; }

    public JweObjectJson(string header, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag)
    {
        Header = header;
        Recipients = recipients;
        Iv = iv;
        CipherText = cipherText;
        AuthTag = authTag;
    }
}