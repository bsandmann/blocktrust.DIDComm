namespace Blocktrust.DIDComm.ProtocolsRouting.ForwardMessages;

using Common.Types;
using Message.Attachments;
using Message.Messages;
using Utils;

class ForwardMessageBuilder
{
    private string _id;
    private string _forwardTo;
    private Dictionary<string, object> _forwardedMsg;

    public ForwardMessageBuilder(string id, string forwardTo, Dictionary<string, object> forwardedMsg)
    {
        this._id = id;
        this._forwardTo = forwardTo;
        this._forwardedMsg = forwardedMsg;
    }

    public ForwardMessage BuildForward()
    {
        var fwmsgBuilder = new MessageBuilder(_id, new Dictionary<string, object> { { "next", this._forwardTo } }, DIDCommMessageProtocolTypes.Forward.ToString());
        //TODO his is also very unclear
        fwmsgBuilder.Attachments = new List<Attachment>
        {
            new AttachmentBuilder(
                DidUtils.DidCommIdGeneratorDefault(),
                Json.Parse(this._forwardedMsg)
            ).Build()
        };


        var message = fwmsgBuilder.build();
        return new ForwardMessage(message, _forwardedMsg, _forwardTo);
    }

    public MessageBuilder CustomHeader(string name, object value)
    {
        //TODO unclear how to implement with the current architecure
        return null;
    }
}