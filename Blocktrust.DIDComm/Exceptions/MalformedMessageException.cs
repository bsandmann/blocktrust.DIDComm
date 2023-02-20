namespace Blocktrust.DIDComm.Exceptions;

public class MalformedMessageException : DidCommException
{
    public MalformedMessageException(string message)
        : base(message)
    {
    }
}
