namespace Blocktrust.DIDComm.Exceptions;

public class UnsupportedJwkException : DidCommUnsupportedValueException
{
    public UnsupportedJwkException(string jwk)
        : base($"The JWK {jwk} is not supported")
    {
    } 
}