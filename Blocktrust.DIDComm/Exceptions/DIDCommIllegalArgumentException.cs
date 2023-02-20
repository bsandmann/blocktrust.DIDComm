namespace Blocktrust.DIDComm.Exceptions;

public class DidCommIllegalArgumentException : DidCommException
{
    public DidCommIllegalArgumentException(string argument)
        : base($"The argument {argument} is not valid")
    {
    }
}