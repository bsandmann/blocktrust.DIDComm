namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text.Json.Serialization;

//TODO rename when JOSE is removed
public class JweRecipientCustom
{
    [JsonPropertyName("header")] public Dictionary<string, object> UnprotectedHeader { get; set; } = new Dictionary<string, object>();
    [JsonPropertyName("encrypted_key")] public string EncryptedKey { get; set; }

    public JweRecipientCustom(Dictionary<string, object> unprotectedHeader, string encryptedKey)
    {
        UnprotectedHeader = unprotectedHeader;
        EncryptedKey = encryptedKey;
    }
}