namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

using Model.UnpackParamsModels;

public class NegativeTestVector<T> where T : Exception
{
    public string packedMessage { get; set; }
    public Type expectedThrow { get; set; }
    public string expectedMessage { get; set; }
    public UnpackParams unpackParams { get; set; }

    public NegativeTestVector(string packedMessage, Type expectedThrow, string expectedMessage, UnpackParams unpackParams = null)
    {
        this.packedMessage = packedMessage;
        this.expectedThrow = expectedThrow;
        this.expectedMessage = expectedMessage;
        if (unpackParams is null)
        {
            this.unpackParams = new UnpackParamsBuilder(packedMessage).BuildUnpackParams();
        }
        else
        {
            this.unpackParams = unpackParams;
        }
    }
}