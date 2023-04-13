namespace Blocktrust.DIDComm.Utils;

using System.Text.Json;
using System.Text.Json.Serialization;

public static class SerializationOptions
{
    public static JsonSerializerOptions UnsafeRelaxedEscaping = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // TODO The default serialization options encode the + sign as \u002B. This is not compatible with Kotlin tests and implementation
        // It can be considered as as security risk, but for now we will use the unsafe relaxed option
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters = { new IDataJsonConverter() }
    };
    
    public static JsonSerializerOptions DisplayIndented = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
}