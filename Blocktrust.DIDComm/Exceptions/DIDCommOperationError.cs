namespace Blocktrust.DIDComm.Exceptions;

public class DidCommOperationError : DidCommException
{
    public DidCommOperationError(string message)
        : base(message)
    {
    }
}