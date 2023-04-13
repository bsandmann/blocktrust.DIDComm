using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Blocktrust.DIDComm.Message.Attachments;

public class IDataJsonConverter : JsonConverter<IData>
{
    public override IData Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using (var jsonDocument = JsonDocument.ParseValue(ref reader))
        {
            var jsonObject = jsonDocument.RootElement.Clone().GetRawText();
            var deserializedJson = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonObject, options);
            return IData.Parse(deserializedJson);
        }
    }

    public override void Write(Utf8JsonWriter writer, IData value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value.ToJsonObject(), options);
    }
}