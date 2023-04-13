namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Blocktrust.Common.Converter;
using Utils;

public class JwsSignatureJson
{
    public JwsSignatureJson()
    {
        
    }
    public JwsSignatureJson(JwsSignature jwsSignature)
    {
        var header = JsonSerializer.Serialize(jwsSignature.ProtectedHeader, SerializationOptions.UnsafeRelaxedEscaping);
        var bytesHeader = Encoding.UTF8.GetBytes(header);
        var headerBase64 = Base64Url.Encode(bytesHeader);
        Protected = headerBase64;
        Signature = jwsSignature.Signature;
        Header = jwsSignature.UnprotectedHeader;
    }

    [JsonPropertyName("protected")]
    public string Protected { get; set; }
    [JsonPropertyName("signature")]
    public string Signature { get; set; }
    [JsonPropertyName("header")]
    public Dictionary<string,object> Header { get; set; }
}