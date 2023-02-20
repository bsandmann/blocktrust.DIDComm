namespace Blocktrust.DIDComm.Message.Messages;

public class MessageHeader
{
    public const string Id = "id";
    public const string Typ = "typ";
    public const string Type = "type";
    public const string From = "from";
    public const string To = "to";
    public const string CreatedTime = "created_time";
    public const string ExpiresTime = "expires_time";
    public const string Body = "body";
    public const string Attachments = "attachments";
    public const string FromPrior = "from_prior";
    public const string PleaseAck = "please_ack";
    public const string Ack = "ack";
    public const string Thid = "thid";
    public const string Pthid = "pthid";

    public static readonly HashSet<string> reservedHeaderNames = new HashSet<string>
    {
        Id, Typ, Type, From, To, CreatedTime, ExpiresTime,
        Body, Attachments, FromPrior, PleaseAck, Ack, Thid, Pthid
    }; 
}