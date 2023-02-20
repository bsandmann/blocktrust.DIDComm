namespace Blocktrust.DIDComm.Exceptions;

public class NotImplementedOperation : DidCommException
{
    public NotImplementedOperation(string message)
        : base(message)
    {
    }
}