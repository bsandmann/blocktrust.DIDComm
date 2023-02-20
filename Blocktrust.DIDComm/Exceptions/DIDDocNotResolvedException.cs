namespace Blocktrust.DIDComm.Exceptions;

using Blocktrust.Common.Exceptions;

public class DidDocNotResolvedException : DidDocException
{
    public DidDocNotResolvedException(string did)
        : base($"The DID Doc '{did}' not resolved")
    {
    }
}