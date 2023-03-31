namespace Blocktrust.DIDComm.ProtocolsRouting.ForwardMessages;

using Message.Attachments;
using Message.Messages;
using Utils;

public class ForwardMessage
{
    public Message Message;
    public Dictionary<string, object> ForwardedMsg;
    public string ForwardNext;

    public ForwardMessage(Message message, Dictionary<string, object> forwardedMsg, string forwardNext)
    {
        this.Message = message;
        this.ForwardedMsg = forwardedMsg;
        this.ForwardNext = forwardNext;
    }

    public static ForwardMessage? FromMessage(Message message)
    {
        string? forwardTo =  message.Body.GetTyped<string>("next");
        if (forwardTo is null)
        {
            return null;
        }

        //TODO is is aboslute trash
        Json? jsonAttachmentData = (Json)message.Attachments?.FirstOrDefault()?.Data;
        var innerJson = jsonAttachmentData?.JsonString;
        var forwardedMsg = innerJson?.GetTyped<Dictionary<string, object>>("json");
        

        // var forwardedMsg = message.Attachments?.First().data.ToJsonObject().GetTyped<Dictionary<string, object>>("json");
        if (forwardedMsg == null) return null;
        if (!(forwardTo is string)) return null;

        return new ForwardMessage(
            message,
            forwardedMsg,
            (string)forwardTo
        );
    }

    public static ForwardMessage Parse(Dictionary<string, object> json)
    {
        return FromMessage(Message.Parse(json));
    }
}