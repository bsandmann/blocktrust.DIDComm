﻿namespace Blocktrust.DIDComm.Message.Attachments;

using System.Collections.Generic;
using System.Linq;
using Exceptions;
using Utils;

public class Attachment
{
    public string Id { get; private set; }
    public IData Data { get; private set; }
    public string? Description { get; private set; }
    public string? Filename { get; private set; }
    public string? MediaType { get; private set; }
    public string? Format { get; private set; }
    public long? LastModTime { get; private set; }
    public long? ByteCount { get; private set; }

    public Attachment(AttachmentBuilder attachmentBuilder)
    {
        this.Id = attachmentBuilder.Id;
        this.Data = attachmentBuilder.Data;
        this.Description = attachmentBuilder.description;
        this.Filename = attachmentBuilder.filename;
        this.MediaType = attachmentBuilder.mediaType;
        this.Format = attachmentBuilder.format;
        this.LastModTime = (long?)attachmentBuilder.lastModTime;
        this.ByteCount = (long?)attachmentBuilder.byteCount;
    }

    public Attachment(string id, IData data)
    {
        this.Id = id;
        this.Data = data;
    }


    public static List<Attachment> Parse(Dictionary<string, object>[] attachments)
    {
        return attachments?.Select(x => Parse(x)).ToList();
    }

    public static Attachment Parse(Dictionary<string, object> json)
    {
        if (json == null)
        {
            return null;
        }

        var id = json.GetTyped<string>(Header.Id)
                 ?? throw new MalformedMessageException($"The header \"id\" is missing");

        var dataObject = json.GetObject(Header.Data);
        if (dataObject is null)
        {
            throw new MalformedMessageException($"The header \"data\" is missing");
        }
        var data = IData.Parse(dataObject);

        var builder = new AttachmentBuilder(id, data);

        foreach (var (key, _) in json)
        {
            switch (key)
            {
                case Header.Id:
                case Header.Data:
                    break;
                case Header.Description:
                    builder.Description(json.GetTyped<string>(key));
                    break;
                case Header.Filename:
                    builder.Filename(json.GetTyped<string>(key));
                    break;
                case Header.MediaType:
                    builder.MediaType(json.GetTyped<string>(key));
                    break;
                case Header.Format:
                    builder.Format(json.GetTyped<string>(key));
                    break;
                case Header.LastmodTime:
                    builder.LastModTime(json.GetTyped<long>(key));
                    break;
                case Header.ByteCount:
                    builder.ByteCount(json.GetTyped<long>(key));
                    break;
                default:
                    throw new MalformedMessageException($"Unknown attachment's header: {key}");
            }
        }

        return builder.Build();
    }
    
    public Dictionary<string, object> ToJSONObject()
    {
        var result = new Dictionary<string, object>()
        {
            { Header.Id, Id },
            { Header.Data, Data.ToJsonObject() },
            { Header.Description, Description },
            { Header.Filename, Filename },
            { Header.MediaType, MediaType },
            { Header.Format, Format },
            { Header.LastmodTime, LastModTime },
            { Header.ByteCount, ByteCount },
        };
        var keysToRemove = new List<string>();
        foreach (var kvp in result)
        {
            if (kvp.Value == null)
            {
                keysToRemove.Add(kvp.Key);
            }
        }

        foreach (var key in keysToRemove)
        {
            result.Remove(key);
        }
        return result;
    }

    public override string ToString()
    {
        return ToJSONObject().ToJsonString();
    }
}