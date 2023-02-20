namespace Blocktrust.DIDComm.Exceptions;

public class DidCommDecodingException : DidCommException
{
    public DidCommDecodingException(string message, Exception innerException = null)
        : base(message, innerException)
    {
    }
}
