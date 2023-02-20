namespace Blocktrust.DIDComm.Exceptions;

public class UnsupportedCurveException : DidCommUnsupportedValueException
{
    public UnsupportedCurveException(string curve)
        : base($"The curve {curve} is not supported")
    {
    } 
}