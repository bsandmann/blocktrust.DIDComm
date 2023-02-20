namespace Blocktrust.DIDComm.Exceptions;

using Blocktrust.Common.Models.DidDoc;

public class UnsupportedSecretMaterialFormatException : DidCommUnsupportedValueException
{
    public UnsupportedSecretMaterialFormatException(VerificationMaterialFormat format, VerificationMethodType type)
        : base($"{format.ToString()} material format is not supported for {type.ToString()} secret type")
    {
    } 
}