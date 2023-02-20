namespace Blocktrust.DIDComm.Exceptions;

public class DidCommActionNotSupported : DidCommException
{
    public DidCommActionNotSupported(string message)
        : base(message)
    {
    }
}