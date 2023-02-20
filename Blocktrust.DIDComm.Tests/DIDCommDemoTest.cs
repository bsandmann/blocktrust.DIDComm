namespace Blocktrust.DIDComm.Tests;

using DIDComm.ProtocolsRouting.Routing;
using DIDComm.Utils;
using FluentAssertions;
using Message.Attachments;
using Message.Messages;
using Model.PackEncryptedParamsModels;
using Model.PackPlaintextParamsModels;
using Model.PackSignedParamsModels;
using Model.UnpackParamsModels;
using TestData.Mock;

public class DIDCommDemoTest
{
    private const string ALICE_DID = "did:example:alice";
    private const string BOB_DID = "did:example:bob";
    private const string CHARLIE_DID = "did:example:charlie";

    [Fact]
    public void Test_repudiable_authentication_encryption_message()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();

        var packResult = didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );

        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        //The problem is, that the unpacked body consits of objects which are JsonElements and this reference-body consists of objects which are strings
        // Assert.Equivalent(message, unpackResult.message);
        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Metadata.Encrypted);
        Assert.True(unpackResult.Metadata.Authenticated);
        Assert.False(unpackResult.Metadata.NonRepudiation);
        Assert.False(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }

    [Fact]
    public void Test_repudiable_non_authenticated_encryption_message()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();

        var packResult = didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID).BuildPackEncryptedParams()
        );

        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Metadata.Encrypted);
        Assert.True(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.Authenticated);
        Assert.False(unpackResult.Metadata.NonRepudiation);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }

    [Fact]
    public void Test_non_repudiable_encryption_message()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object>() { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();

        var packResult = didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams());


        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Metadata.Encrypted);
        Assert.True(unpackResult.Metadata.Authenticated);
        Assert.True(unpackResult.Metadata.NonRepudiation);
        Assert.False(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }

    [Fact]
    public void Test_non_repudiable_encryption_message_for_anonymous_sender()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object>() { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();

        var packResult = didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .ProtectSenderId(true)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );
    
        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );
    
        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Metadata.Encrypted);
        Assert.True(unpackResult.Metadata.Authenticated);
        Assert.True(unpackResult.Metadata.NonRepudiation);
        Assert.True(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }

    [Fact]
    public void Test_signed_unencrypted_message()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();

        var packResult = didComm.PackSigned(
            new PackSignedParamsBuilder(message, ALICE_DID).BuildPackSginedParams()
        );

        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage).BuildUnpackParams()
        );
        
        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Metadata.NonRepudiation);
        Assert.True(unpackResult.Metadata.Authenticated);
        Assert.False(unpackResult.Metadata.Encrypted);
        Assert.False(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }

    [Fact]
    public void Test_plaintext_message()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();

        var packResult = didComm.PackPlaintext(
            new PackPlaintextParamsBuilder(message).BuildPackPlaintext()
        );

        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage).BuildUnpackParams()
        );

        //The problem is, that the unpacked body consits of objects which are JsonElements and this reference-body consists of objects which are strings
        // Assert.Equivalent(message, unpackResult.message);
        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
        Assert.False(unpackResult.Metadata.NonRepudiation);
        Assert.False(unpackResult.Metadata.Encrypted);
        Assert.False(unpackResult.Metadata.Authenticated);
        Assert.False(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }

    [Fact]
    public void Test_multi_recipient_support()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var routing = new Routing(new DidDocResolverMock(), new AliceSecretResolverMock());
        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID, CHARLIE_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();
    
        var packResultBob = didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .ProtectSenderId(true)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );
        
        var unpackResultBob = didComm.Unpack(
            new UnpackParamsBuilder(packResultBob.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );
        
        Assert.True(unpackResultBob.Metadata.Encrypted);
        Assert.True(unpackResultBob.Metadata.Authenticated);
        Assert.True(unpackResultBob.Metadata.NonRepudiation);
        Assert.True(unpackResultBob.Metadata.AnonymousSender);
        Assert.False(unpackResultBob.Metadata.ReWrappedInForward);

        var packResultCharlie = didComm.PackEncrypted(
            PackEncryptedParams.Builder(message, CHARLIE_DID)
                .ProtectSenderId(true)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );
        
    
        var forwardCharlie = routing.UnpackForward(
            packResultCharlie.PackedMessage,
            secretResolver: new Mediator2SecretResolverMock()
        );
    
        var forwardedMsg = JsonUtils.ToJson(forwardCharlie.ForwardMsg.ForwardedMsg);
    
        forwardCharlie = routing.UnpackForward(
            forwardedMsg,
            secretResolver: new Mediator1SecretResolverMock()
        );
    
        forwardedMsg = JsonUtils.ToJson(forwardCharlie.ForwardMsg.ForwardedMsg);
    
        var unpackResultCharlie = didComm.Unpack(
            new UnpackParamsBuilder(forwardedMsg)
                .SecretResolver(new CharlieSecretResolverMock())
                .BuildUnpackParams()
        );
        
        Assert.True(unpackResultCharlie.Metadata.Encrypted);
        Assert.True(unpackResultCharlie.Metadata.Authenticated);
        Assert.True(unpackResultCharlie.Metadata.NonRepudiation);
        Assert.True(unpackResultCharlie.Metadata.AnonymousSender);
        Assert.False(unpackResultCharlie.Metadata.ReWrappedInForward);
    
        //TODO
        message.Should().BeEquivalentTo(unpackResultBob.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResultBob.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResultBob.Message.Body.First().Key);
       
        //TODO
        message.Should().BeEquivalentTo(unpackResultCharlie.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResultCharlie.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResultCharlie.Message.Body.First().Key);
        
        unpackResultBob.Message.To = null;
        unpackResultBob.Metadata.EncryptedTo = null;
        unpackResultBob.Metadata.SignedMessage = null;
        unpackResultBob.Metadata.EncryptedTo = null;
        unpackResultBob.Metadata.SignedMessage = null;
        unpackResultCharlie.Message.To = null;
        unpackResultCharlie.Metadata.EncryptedTo = null;
        unpackResultCharlie.Metadata.SignedMessage = null;
        unpackResultCharlie.Metadata.EncryptedTo = null;
        unpackResultCharlie.Metadata.SignedMessage = null;
        unpackResultBob.Message.Should().BeEquivalentTo(unpackResultCharlie.Message, options => options.Excluding(x => x.Body));
        unpackResultBob.Metadata.Should().BeEquivalentTo(unpackResultCharlie.Metadata);
    }

    [Fact]
    public void Test_encrypt_message_with_attachments()
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

        var message = Message.Builder("12345", new Dictionary<string, object> { { "foo", "bar" } }, "my-protocol/1.0")
            .attachments(attachments)
            .from(ALICE_DID)
            .to(new List<string> { BOB_DID })
            .build();

        var packResult = didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID).BuildPackEncryptedParams()
        );

        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        message.Should().BeEquivalentTo(unpackResult.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Message.Body.First().Value?.ToString());
    }
}