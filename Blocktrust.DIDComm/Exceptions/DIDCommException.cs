namespace Blocktrust.DIDComm.Exceptions;

public class DidCommException : Exception
{
    public DidCommException(string message, Exception innerException = null)
        : base(message, innerException)
    {
    }
}