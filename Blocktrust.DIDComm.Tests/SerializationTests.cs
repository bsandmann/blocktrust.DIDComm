namespace Blocktrust.DIDComm.Tests;

using System.Text.Json;
using Blocktrust.Common.Converter;
using DIDComm.Utils;
using FluentAssertions;
using Message.Attachments;
using TestData.Mock;

public class SerializationTests
{
    private const string ALICE_DID = "did:example:alice";
    private const string BOB_DID = "did:example:bob";

    [Fact]
    public async Task Message_with_attachments_serializes_correctly()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var attachments = new List<Attachment>
        {
            new AttachmentBuilder("1", new Base64("SGVsbG8sIHdvcmxk"))
                .MediaType("text/plain")
                .Build(),

            new AttachmentBuilder("2", new Json(new Dictionary<string, object> { { "foo", "bar" } }))
                .Description("The second attachment")
                .MediaType("application/json")
                .Build()
        };

        var message = Blocktrust.DIDComm.Message.Messages.Message.Builder("12345", new Dictionary<string, object> { { "foo", "bar" } }, "my-protocol/1.0")
            .attachments(attachments)
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .build();
        
       var serializedMessage = JsonSerializer.Serialize(message, SerializationOptions.UnsafeRelaxedEscaping); 
       var unserializedMessage = JsonSerializer.Deserialize<Blocktrust.DIDComm.Message.Messages.Message>(serializedMessage, SerializationOptions.UnsafeRelaxedEscaping);

       unserializedMessage.Attachments.Count.Should().Be(2);
       unserializedMessage.Attachments[0].Id.Should().Be("1");
       unserializedMessage.Attachments[1].Id.Should().Be("2");
    }
}