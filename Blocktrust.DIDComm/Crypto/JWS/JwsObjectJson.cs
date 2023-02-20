namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text.Json.Serialization;

public class JwsObjectJson
{
    [JsonPropertyName("payload")] public string Payload { get; set; }
    [JsonPropertyName("signatures")] public List<JwsSignatureJson> Signatures { get; set; }
}