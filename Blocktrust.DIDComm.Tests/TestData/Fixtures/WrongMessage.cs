namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

public class WrongMessage
{
    public WrongMessage(string json, string expectedMessage)
    {
        Json = json;
        ExpectedMessage = expectedMessage;
    }

    public string Json { get; }
    public string ExpectedMessage { get; }
}