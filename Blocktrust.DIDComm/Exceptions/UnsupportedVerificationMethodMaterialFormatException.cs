namespace Blocktrust.DIDComm.Exceptions;

using Blocktrust.Common.Models.DidDoc;

public class UnsupportedVerificationMethodMaterialFormatException : DidCommUnsupportedValueException
{
    public UnsupportedVerificationMethodMaterialFormatException(VerificationMaterialFormat format, VerificationMethodType type)
        : base($"{format.ToString()} material format is not supported for {type.ToString()} verification method type")
    {
    }
}