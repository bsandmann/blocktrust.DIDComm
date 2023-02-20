namespace Blocktrust.DIDComm.Exceptions;

public class DidCommActionAborted : DidCommException
{
    public DidCommActionAborted(string message)
        : base(message)
    {
    }
}