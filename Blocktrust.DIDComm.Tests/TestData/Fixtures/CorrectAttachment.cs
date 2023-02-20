namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

public class CorrectAttachment
{
    public CorrectAttachment(string json, List<ExpectedAttachmentData> expectedAttachmentData)
    {
        Json = json;
        ExpectedAttachmentData = expectedAttachmentData;
    }

    public string Json { get; }
    public List<ExpectedAttachmentData> ExpectedAttachmentData { get; }
}