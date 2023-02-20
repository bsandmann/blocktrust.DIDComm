namespace Blocktrust.DIDComm.Exceptions;

using Blocktrust.Common.Exceptions;

public class DidCommServiceException : DidDocException
{
    public DidCommServiceException(string did, string msg)
        : base($"Invalid DIDCommService for DID Doc '{did}': {msg}")
    {
    }
}