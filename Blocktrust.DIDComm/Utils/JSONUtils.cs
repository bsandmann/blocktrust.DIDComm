namespace Blocktrust.DIDComm.Utils;

using System.Collections.Generic;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Exceptions;

public static class JsonUtils
{
    public static T[] GetTypedArray<T>(this Dictionary<string, object> map, string key)
    {
        if (map.TryGetValue(key, out var value))
        {
            var jsonElement = (JsonElement)value;
            var valueKind = jsonElement.ValueKind;
            if (valueKind == JsonValueKind.Array)
            {
                var array = new T[jsonElement.GetArrayLength()];
                for (var i = 0; i < array.Length; i++)
                {
                    //TODO not so beautiful
                    try
                    {
                        array[i] = JsonSerializer.Deserialize<T>(jsonElement[i].GetRawText().Trim());
                    }
                    catch (Exception _)
                    {
                        throw new MalformedMessageException($"The expected type of header '{key}' is 'List'. Got '{jsonElement[i].ValueKind}'");
                    }
                }

                return array;
            }
            else
            {
                throw new MalformedMessageException($"The expected type of header '{key}' is 'List'. Got '{valueKind}'");
            }
        }

        return null;
    }

    public static T GetTyped<T>(this Dictionary<string, object> map, string key)
    {
        if (map.TryGetValue(key, out var value))
        {
            if (value is null)
            {
                return default(T);
            }

            if (value is string)
            {
                return (T)value;
            }

            var jsonElement = (JsonElement)value;
            var valueKind = jsonElement.ValueKind;
            try
            {
                return valueKind switch
                {
                    //TODO This causes the value of inner object to be a JsonElement. This is fine for me, but doesnt match the tests
                    //So I have a seperate methode to build the objects in a way, the the inner objects are strings.
                    //This then works for the tests, but it is unclear what is required in real world use cases.

                    JsonValueKind.Object => JsonSerializer.Deserialize<T>(jsonElement!.GetRawText()),
                    JsonValueKind.Array => JsonSerializer.Deserialize<T>(jsonElement!.GetRawText()),
                    JsonValueKind.String => JsonSerializer.Deserialize<T>(jsonElement.GetRawText()),
                    JsonValueKind.Number => JsonSerializer.Deserialize<T>(jsonElement.GetRawText()),
                    JsonValueKind.True => JsonSerializer.Deserialize<T>(jsonElement.GetRawText()),
                    JsonValueKind.False => JsonSerializer.Deserialize<T>(jsonElement.GetRawText()),
                    JsonValueKind.Null => JsonSerializer.Deserialize<T>(jsonElement.GetRawText()),
                    _ => throw new MalformedMessageException($"The expected type of header '{key}' is '{typeof(T).Name}'. Got '{valueKind}'")
                };
            }
            catch (Exception e)
            {
                throw new MalformedMessageException($"The expected type of header '{key}' is '{typeof(T).Name}'. Got '{valueKind}'");
            }
        }

        return default(T);
    }

    //See above for the reason for the differnt implementation
    public static Dictionary<string, object> GetObject(this Dictionary<string, object> map, string key)
    {
        if (map.TryGetValue(key, out var value))
        {
            if (value is null)
            {
                return default;
            }

            var jsonElement = (JsonElement)value;
            var valueKind = jsonElement.ValueKind;
            if (valueKind is not JsonValueKind.Object)
            {
                throw new MalformedMessageException($"The expected type of header '{key}' is 'Dictionary'. Got '{valueKind}'");
            }
            else
            {
                var dictionary = new Dictionary<string, object>();
                foreach (var jsonEntry in jsonElement.EnumerateObject())
                {
                    dictionary.Add(jsonEntry.Name, jsonEntry.Value);
                }

                return dictionary;
            }
        }

        return default;
    }

    public static T[] GetTyped<T>(this List<object> list, string key)
    {
        return list.Select(x =>
        {
            if (x == null)
            {
                return default(T);
            }
            else if (x is T typedValue)
            {
                return typedValue;
            }
            else
            {
                throw new MalformedMessageException($"The expected type of header '{key}' is '{typeof(T).Name}'. Got '{x.GetType().Name}'");
            }
        }).ToArray();
    }

    public static string ToJsonString(this Dictionary<string, object> map) => System.Text.Json.JsonSerializer.Serialize(map, SerializationOptions.UnsafeRelaxedEscaping);

    public static string ToJson(object value) =>
        System.Text.Json.JsonSerializer.Serialize(value, SerializationOptions.UnsafeRelaxedEscaping);

    public static Dictionary<string, object> FromJsonToMap(string value) =>
        System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(value);

   
}