namespace Blocktrust.DIDComm.Exceptions;

public class DidCommCredentialNotAcceptable : DidCommException
{
    public DidCommCredentialNotAcceptable(string message)
        : base(message)
    {
    }
}