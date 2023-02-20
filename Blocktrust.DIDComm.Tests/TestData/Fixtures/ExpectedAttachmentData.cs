namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

public class ExpectedAttachmentData
{
    public ExpectedAttachmentData(bool isJson = false, bool isLinks = false, bool isBase64 = false)
    {
        IsJson = isJson;
        IsLinks = isLinks;
        IsBase64 = isBase64;
    }

    public bool IsJson { get; }
    public bool IsLinks { get; }
    public bool IsBase64 { get; }
}