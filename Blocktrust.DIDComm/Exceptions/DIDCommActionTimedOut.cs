namespace Blocktrust.DIDComm.Exceptions;

public class DidCommActionTimedOut : DidCommException
{
    public DidCommActionTimedOut(string message)
        : base(message)
    {
    }
}