namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

using Model.UnpackResultModels;

public class JWSTestVector
{
    public string from { get; set; }
    public string expected { get; set; }
    public Metadata expectedMetadata { get; set; }

    public JWSTestVector(string from, string expected, Metadata expectedMetadata)
    {
        this.from = from;
        this.expected = expected;
        this.expectedMetadata = expectedMetadata;
    }
}