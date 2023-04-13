namespace Blocktrust.DIDComm.Message.Messages;

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Attachments;
using Blocktrust.Common.Converter;
using Exceptions;
using FromPriors;
using Utils;

public class Message
{
    [JsonPropertyName("id")] public string Id { get; set; }
    [JsonPropertyName("body")] public Dictionary<string, object?> Body { get; set; }
    [JsonPropertyName("type")] public string Type { get; set; }
    [JsonPropertyName("typ")] public string Typ { get; set; }
    [JsonPropertyName("from")] public string? From { get; set; }
    [JsonPropertyName("to")] public IList<string>? To { get; set; }
    [JsonPropertyName("created_time")] public long? CreatedTime { get; set; }
    [JsonPropertyName("expires_time")] public long? ExpiresTime { get; set; }
    [JsonPropertyName("from_prior")] public FromPrior? FromPrior { get; set; }
    [JsonPropertyName("fromPriorJwt")] public string? FromPriorJwt { get; set; }
    [JsonPropertyName("attachments")] public IList<Attachment>? Attachments { get; set; }
    [JsonPropertyName("please_ack")] public bool? PleaseAck { get; set; }
    [JsonPropertyName("ack")] public string? Ack { get; set; }
    [JsonPropertyName("thid")] public string? Thid { get; set; }
    [JsonPropertyName("pthid")] public string? Pthid { get; set; }
    [JsonPropertyName("customHeaders")] public Dictionary<string, object?> CustomHeaders { get; } = new Dictionary<string, object?>();


    [JsonConstructor]
    public Message()
    {
        
    }
    
    public T CustomHeader<T>(string name)
    {
        return CustomHeaders.GetTyped<T>(name);
    }

    public Dictionary<string, object?> CustomHeaderObject(string name)
    {
        //TODO not very elegant
        var jsonElement = (JsonElement)CustomHeaders[name];
        var jsonElementString = jsonElement.GetRawText();
        var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonElementString);
        return dictionary;
    }

    public IList<T> CustomHeaderArray<T>(string name)
    {
        return CustomHeaders.GetTypedArray<T>(name);
    }

    internal Message(MessageBuilder builder)
    {
        Id = builder.Id;
        Body = builder.Body;
        Type = builder.Type;
        Typ = builder.Typ;
        From = builder.From;
        To = builder.To;
        CreatedTime = builder.CreatedTime;
        ExpiresTime = builder.ExpiresTime;
        FromPrior = builder.FromPrior;
        FromPriorJwt = builder.FromPriorJwt;
        Attachments = builder.Attachments;
        PleaseAck = builder.PleaseAck;
        Ack = builder.Ack;
        Thid = builder.Thid;
        Pthid = builder.Pthid;
        CustomHeaders = builder.CustomHeaders;
    }

    public static MessageBuilder Builder(string id, Dictionary<string, object> body, string type)
    {
        return new MessageBuilder(id, body, type);
    }

    public static Message Parse(Dictionary<string, object> json)
    {
        string id = json.GetTyped<string>(MessageHeader.Id)
                    ?? throw new MalformedMessageException("The header \"id\" is missing");

        Dictionary<string, object> body = json.GetObject(MessageHeader.Body)
                                          ?? throw new MalformedMessageException("The header \"body\" is missing");

        string type = json.GetTyped<string>(MessageHeader.Type)
                      ?? throw new MalformedMessageException("The header \"type\" is missing");

        MessageBuilder builder = Builder(id, body, type);

        foreach (string key in json.Keys)
        {
            switch (key)
            {
                case MessageHeader.Id:
                case MessageHeader.Typ:
                case MessageHeader.Type:
                case MessageHeader.Body:
                    break;
                case MessageHeader.From:
                    builder.from(json.GetTyped<string>(key));
                    break;
                case MessageHeader.To:
                    builder.to(json.GetTyped<List<string>>(key));
                    break;
                case MessageHeader.CreatedTime:
                    builder.createdTime(json.GetTyped<long>(key));
                    break;
                case MessageHeader.ExpiresTime:
                    builder.expiresTime(json.GetTyped<long>(key));
                    break;
                case MessageHeader.Attachments:
                    builder.attachments(Attachment.Parse(json.GetTypedArray<Dictionary<string, object>>(MessageHeader.Attachments)));
                    break;
                case MessageHeader.FromPrior:
                    builder.fromPriorJwt(json.GetTyped<string>(key));
                    break;
                case MessageHeader.PleaseAck:
                    builder.pleaseAck(json.GetTyped<bool?>(key));
                    break;
                case MessageHeader.Ack:
                    builder.ack(json.GetTyped<string>(key));
                    break;
                case MessageHeader.Thid:
                    builder.thid(json.GetTyped<string>(key));
                    break;
                case MessageHeader.Pthid:
                    builder.pthid(json.GetTyped<string>(key));
                    break;
                default:
                    builder.customHeader(key, json[key]);
                    break;
            }
        }

        return builder.build();
    }

    public Dictionary<string, object?> ToJSONObject()
    {
        //TODO this code doesn not get execute yet.
        // but it doesn some very important things reagridn mapping

        var obj = new Dictionary<string, object?>
        {
            { MessageHeader.Id, Id },
            { MessageHeader.Typ, Typ },
            { MessageHeader.Type, Type },
            { MessageHeader.From, From },
            { MessageHeader.To, To },
            { MessageHeader.CreatedTime, CreatedTime },
            { MessageHeader.ExpiresTime, ExpiresTime },
            { MessageHeader.Body, Body },
            { MessageHeader.Attachments, Attachments?.Select(x => x.ToJSONObject()).ToList() },
            { MessageHeader.FromPrior, FromPriorJwt },
            { MessageHeader.PleaseAck, PleaseAck },
            { MessageHeader.Ack, Ack },
            { MessageHeader.Thid, Thid },
            { MessageHeader.Pthid, Pthid },
        };

        foreach (var header in CustomHeaders)
        {
            obj.Add(header.Key, header.Value);
        }

        return obj.Where(x => x.Value != null).ToDictionary(x => x.Key, x => x.Value);
    }

    public override string ToString()
    {
        var remappedMessage = this.ToJSONObject();
        var serialization = System.Text.Json.JsonSerializer.Serialize(remappedMessage, SerializationOptions.UnsafeRelaxedEscaping);
        return serialization;
    }

    public Message Copy(List<Attachment> attachments)
    {
        foreach (var attachment in attachments)
        {
            this.Attachments?.Add(attachment);
        }

        return this;
    }
}