namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Utils;

public class JwsPayload
{
    public JwsPayload(string base64, bool isBase64UrlEncoded)
    {
        if (isBase64UrlEncoded == false)
        {
            throw new Exception("Shitty desing");
        }
        Base64 = base64;
        Base64ToJsonDictionary();
        Base64ToJsonString();
    }
    
    public JwsPayload(string jsonString)
    {
        JsonString = jsonString;
        JsonStringToBase64();
    }
    
    public JwsPayload(Dictionary<string,object> jsonDictionary)
    {
        JsonDictionary = jsonDictionary;
        JsonDictionaryToBase64();
    }


    //Base64Url encoded
    public string Base64 { get; private set; }
    
    public string JsonString { get;private set; }
    public Dictionary<string, object> JsonDictionary { get; private set; }
    
    
    private void Base64ToJsonDictionary()
    {
        var payloadBytes = Base64Url.Decode(Base64);
        var payloadString = Encoding.UTF8.GetString(payloadBytes);
        JsonDictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadString);
    }

    private void JsonDictionaryToBase64()
    {
        var payloadJson = JsonSerializer.Serialize(JsonDictionary, SerializationOptions.UnsafeRelaxedEscaping);
        var payloadString = Encoding.UTF8.GetBytes(payloadJson);
        Base64 = Base64Url.Encode(payloadString);
    }
    
    private void JsonStringToBase64()
    {
        var payloadBytes = Encoding.UTF8.GetBytes(JsonString);
        Base64 = Base64Url.Encode(payloadBytes);
    }
    
    private void Base64ToJsonString()
    {
        var payloadBytes = Base64Url.Decode(Base64);
        JsonString = Encoding.UTF8.GetString(payloadBytes);
    }
}