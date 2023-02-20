namespace Blocktrust.DIDComm.Exceptions;

public class IncompatibleCryptoException : DidCommException
{
    public IncompatibleCryptoException(string message)
        : base(message)
    {
    }
}