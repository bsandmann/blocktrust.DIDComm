namespace Blocktrust.DIDComm.Exceptions;

public class SecretNotFoundException : DidCommException
{
    public SecretNotFoundException(string kid)
        : base($"The Secret '{kid}' not found")
    {
    }
}