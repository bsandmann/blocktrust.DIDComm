namespace Blocktrust.DIDComm.Message.Attachments;

public class AttachmentBuilder
{
    public string Id { get; }
    public IData Data { get; }
    public string filename { get; private set; }
    public string format { get; private set; }
    public long? lastModTime { get; private set; }
    public string description { get; private set; }
    public string mediaType { get; private set; }
    public long? byteCount { get; private set; }

    public AttachmentBuilder(string id, IData data)
    {
        this.Id = id;
        this.Data = data;
    }

    public AttachmentBuilder Filename(string filename)
    {
        this.filename = filename;
        return this;
    }

    public AttachmentBuilder LastModTime(long? lastModTime)
    {
        this.lastModTime = lastModTime;
        return this;
    }

    public AttachmentBuilder Format(string format)
    {
        this.format = format;
        return this;
    }

    public AttachmentBuilder Description(string description)
    {
        this.description = description;
        return this;
    }

    public AttachmentBuilder MediaType(string mediaType)
    {
        this.mediaType = mediaType;
        return this;
    }

    public AttachmentBuilder ByteCount(long? byteCount)
    {
        this.byteCount = byteCount;
        return this;
    }

    public Attachment Build()
    {
        return new Attachment(this);
    }
}