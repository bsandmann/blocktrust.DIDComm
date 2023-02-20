namespace Blocktrust.DIDComm.ProtocolsRouting.Routing;

using ForwardMessages;
using Model.PackEncryptedResultModels;

public class WrapInForwardResult
{
    public ForwardMessage Msg;
    public PackEncryptedResult MsgEncrypted;

    public WrapInForwardResult(ForwardMessage msg, PackEncryptedResult msgEncrypted)
    {
        this.Msg = msg;
        this.MsgEncrypted = msgEncrypted;
    }
}