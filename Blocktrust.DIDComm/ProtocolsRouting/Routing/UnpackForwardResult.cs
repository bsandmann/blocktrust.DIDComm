namespace Blocktrust.DIDComm.ProtocolsRouting.Routing;

using ForwardMessages;

public class UnpackForwardResult
{
    public ForwardMessage ForwardMsg;
    public List<string> ForwardedMsgEncryptedTo;

    public UnpackForwardResult(ForwardMessage forwardMsg, List<string> forwardedMsgEncryptedTo = null)
    {
        this.ForwardMsg = forwardMsg;
        this.ForwardedMsgEncryptedTo = forwardedMsgEncryptedTo;
    }
}