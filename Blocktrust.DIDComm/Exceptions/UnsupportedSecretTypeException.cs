namespace Blocktrust.DIDComm.Exceptions;

using Blocktrust.Common.Models.DidDoc;

public class UnsupportedSecretTypeException : DidCommUnsupportedValueException
{
    public UnsupportedSecretTypeException(VerificationMethodType type)
        : base($"{type.ToString()} secret type is not supported")
    {
    } 
}