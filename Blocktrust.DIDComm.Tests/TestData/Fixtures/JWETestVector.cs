namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

using Model.UnpackResultModels;

public class JWETestVector
{
    public string message { get; set; }
    public Metadata expectedMetadata { get; set; }

    public JWETestVector(string message, Metadata expectedMetadata)
    {
        this.message = message;
        this.expectedMetadata = expectedMetadata;
    } 
}