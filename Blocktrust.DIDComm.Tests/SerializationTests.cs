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
        unserializedMessage.Attachments[0].Data.ToJsonObject().ToJsonString().Should().Be("""{"jws":null,"hash":null,"base64":"SGVsbG8sIHdvcmxk"}""");
        unserializedMessage.Attachments[1].Id.Should().Be("2");
        unserializedMessage.Attachments[1].Data.ToJsonObject().ToJsonString().Should().Be("""{"jws":null,"hash":null,"json":{"foo":"bar"}}""");
    }

    [Fact]
    public async Task Message_with_attachments_serializes_correctly_2()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var otherStuff = new Dictionary<string, object>
        {
            { "challenge", "x" },
            { "nonce", "y" },
            { "domain", "z" }
        };
        var presentation = new Dictionary<string, object>
        {
            { "id", "x" },
            { "name", "y" },
            { "purpose", "z" },
            {
                "format", new Dictionary<string, object>()
                {
                    {
                        "jwt", new Dictionary<string, object>()
                        {
                            { "alg", "abc" },
                            { "proof_type", null }
                        }
                    }
                }
            }
        };
        var attachments = new List<Attachment>
        {
            new AttachmentBuilder("1", new Json(new Dictionary<string, object>
                {
                    { "options", otherStuff },
                    { "presentation_definition", presentation}
                }))
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

        unserializedMessage.Attachments.Count.Should().Be(1);
        unserializedMessage.Attachments[0].Id.Should().Be("1");
        unserializedMessage.Attachments[0].Data.ToJsonObject().ToJsonString().Should().Be("""{"jws":null,"hash":null,"json":{"options":{"challenge":"x","nonce":"y","domain":"z"},"presentation_definition":{"id":"x","name":"y","purpose":"z","format":{"jwt":{"alg":"abc","proof_type":null}}}}}""");
    }
}