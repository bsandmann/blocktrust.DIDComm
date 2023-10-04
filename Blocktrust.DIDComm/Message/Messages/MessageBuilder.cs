namespace Blocktrust.DIDComm.Message.Messages;

using Attachments;
using Common.Types;
using Exceptions;
using FromPriors;
using Utils;

public class MessageBuilder
{
    public string Id { get; set; }
    public Dictionary<string, object>? Body { get; set; }
    public string Type { get; set; }

    internal string Typ { get; set; }

    public string? From { get; private set; }

    internal List<string>? To { get; private set; }

    internal long? CreatedTime { get; private set; }

    internal long? ExpiresTime { get; private set; }

    internal Dictionary<string, object?> CustomHeaders { get; private set; } = new Dictionary<string, object?>();

    internal List<Attachment> Attachments { get; set; }

    internal FromPrior? FromPrior { get; private set; }

    internal string? FromPriorJwt { get; private set; }

    internal bool? PleaseAck { get; private set; }

    internal string? Ack { get; private set; }

    internal string? Thid { get; private set; }

    internal string? Pthid { get; private set; }
    internal string? ReturnRoute { get; private set; }

    public MessageBuilder(string id, Dictionary<string, object> body, string type)
    {
        this.Id = id;
        this.Body = body;
        this.Type = type;
        this.Typ = MessageTyp.Plaintext;
    }

    public MessageBuilder from(string? from)
    {
        if (from != null && DidUtils.IsDidFragment(from))
            throw new DidCommIllegalArgumentException(from);
        this.From = from;
        return this;
    }

    public MessageBuilder to(List<string>? to)
    {
        if (to != null && to.Any(x => DidUtils.IsDidFragment(x)))
            throw new DidCommIllegalArgumentException(to.ToString());
        this.To = to;
        return this;
    }

    public MessageBuilder createdTime(long? createdTime)
    {
        this.CreatedTime = createdTime;
        return this;
    }

    public MessageBuilder expiresTime(long? expiresTime)
    {
        this.ExpiresTime = expiresTime;
        return this;
    }

    public MessageBuilder fromPrior(FromPrior? fromPrior)
    {
        this.FromPrior = fromPrior;
        return this;
    }

    public MessageBuilder fromPriorJwt(string fromPriorJwt)
    {
        this.FromPriorJwt = fromPriorJwt;
        return this;
    }

    public MessageBuilder attachments(List<Attachment> attachments)
    {
        this.Attachments = attachments;
        return this;
    }

    public MessageBuilder pleaseAck(bool? pleaseAck)
    {
        this.PleaseAck = pleaseAck;
        return this;
    }

    public MessageBuilder ack(string ack)
    {
        this.Ack = ack;
        return this;
    }

    public MessageBuilder thid(string thid)
    {
        this.Thid = thid;
        return this;
    }

    public MessageBuilder pthid(string pthid)
    {
        this.Pthid = pthid;
        return this;
    }
    
    public MessageBuilder returnRoute(string returnRoute)
    {
        this.ReturnRoute = returnRoute;
        return this;
    }

    public MessageBuilder customHeader (string name, object value)
    {
        if (MessageHeader.reservedHeaderNames.Contains(name))
            throw new DidCommException($"The header name '{name}' is reserved");
        CustomHeaders[name] = value;
        return this;
    }

    public Message build()
    {
        return new Message(this);
    }
}