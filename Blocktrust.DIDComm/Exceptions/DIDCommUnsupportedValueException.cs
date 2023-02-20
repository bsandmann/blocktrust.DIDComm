namespace Blocktrust.DIDComm.Exceptions;

public class DidCommUnsupportedValueException : DidCommException
{
    public DidCommUnsupportedValueException(string message, Exception innerException = null)
        : base(message, innerException)
    {
    } 
}