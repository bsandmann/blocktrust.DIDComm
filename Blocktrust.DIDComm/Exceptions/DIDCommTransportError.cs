namespace Blocktrust.DIDComm.Exceptions;

public class DidCommTransportError : DidCommException
{
    public DidCommTransportError(string message)
        : base(message)
    {
    }
}