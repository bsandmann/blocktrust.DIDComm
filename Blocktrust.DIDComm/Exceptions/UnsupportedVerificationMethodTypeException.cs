namespace Blocktrust.DIDComm.Exceptions;

using Blocktrust.Common.Models.DidDoc;

public class UnsupportedVerificationMethodTypeException : DidCommUnsupportedValueException
{
    public UnsupportedVerificationMethodTypeException(VerificationMethodType type)
        : base($"{type.ToString()} verification method type is not supported")
    {
    } 
}