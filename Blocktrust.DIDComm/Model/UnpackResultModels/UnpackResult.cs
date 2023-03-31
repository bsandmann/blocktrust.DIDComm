namespace Blocktrust.DIDComm.Model.UnpackResultModels;

using Message.Messages;

public class UnpackResult
{
    public readonly Message Message;
    public readonly Metadata Metadata;

    public UnpackResult(Message message, Metadata metadata)
    {
        this.Message = message;
        this.Metadata = metadata;
    } 
}