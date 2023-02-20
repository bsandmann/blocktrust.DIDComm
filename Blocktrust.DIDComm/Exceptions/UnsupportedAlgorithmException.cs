namespace Blocktrust.DIDComm.Exceptions;

public class UnsupportedAlgorithmException : DidCommUnsupportedValueException
{
    public UnsupportedAlgorithmException(string alg, Exception innerException = null)
        : base($"The algorithm {alg} is not supported", innerException)
    {
    }
}