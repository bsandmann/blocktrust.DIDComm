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
    public async Task Test_repudiable_authentication_encryption_message()
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

        var packResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );

        var unpackResult = await didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        //The problem is, that the unpacked body consits of objects which are JsonElements and this reference-body consists of objects which are strings
        // Assert.Equivalent(message, unpackResult.message);
        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Value.Metadata.Encrypted);
        Assert.True(unpackResult.Value.Metadata.Authenticated);
        Assert.False(unpackResult.Value.Metadata.NonRepudiation);
        Assert.False(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }

    [Fact]
    public async Task Test_repudiable_non_authenticated_encryption_message()
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

        var packResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID).BuildPackEncryptedParams()
        );

        var unpackResult = await didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Value.Metadata.Encrypted);
        Assert.True(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.Authenticated);
        Assert.False(unpackResult.Value.Metadata.NonRepudiation);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }

    [Fact]
    public async Task Test_non_repudiable_encryption_message()
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

        var packResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams());


        var unpackResult = await didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Value.Metadata.Encrypted);
        Assert.True(unpackResult.Value.Metadata.Authenticated);
        Assert.True(unpackResult.Value.Metadata.NonRepudiation);
        Assert.False(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }

    [Fact]
    public async Task Test_non_repudiable_encryption_message_for_anonymous_sender()
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

        var packResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .ProtectSenderId(true)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );
    
        var unpackResult = await didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );
    
        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Value.Metadata.Encrypted);
        Assert.True(unpackResult.Value.Metadata.Authenticated);
        Assert.True(unpackResult.Value.Metadata.NonRepudiation);
        Assert.True(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }

    [Fact]
    public async Task Test_signed_unencrypted_message()
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

        var packResult = await didComm.PackSigned(
            new PackSignedParamsBuilder(message, ALICE_DID).BuildPackSginedParams()
        );

        var unpackResult =await  didComm.Unpack(
            new UnpackParamsBuilder(packResult.Value.PackedMessage).BuildUnpackParams()
        );
        
        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.True(unpackResult.Value.Metadata.NonRepudiation);
        Assert.True(unpackResult.Value.Metadata.Authenticated);
        Assert.False(unpackResult.Value.Metadata.Encrypted);
        Assert.False(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }

    [Fact]
    public async Task Test_plaintext_message()
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

        var packResult = await didComm.PackPlaintext(
            new PackPlaintextParamsBuilder(message).BuildPackPlaintext()
        );

        var unpackResult =await  didComm.Unpack(
            new UnpackParamsBuilder(packResult.Value.PackedMessage).BuildUnpackParams()
        );

        //The problem is, that the unpacked body consits of objects which are JsonElements and this reference-body consists of objects which are strings
        // Assert.Equivalent(message, unpackResult.Value.message);
        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.False(unpackResult.Value.Metadata.NonRepudiation);
        Assert.False(unpackResult.Value.Metadata.Encrypted);
        Assert.False(unpackResult.Value.Metadata.Authenticated);
        Assert.False(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }

    [Fact]
    public async Task Test_multi_recipient_support()
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
    
        var packResultBob = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID)
                .ProtectSenderId(true)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );
        
        var unpackResultBob =await  didComm.Unpack(
            new UnpackParamsBuilder(packResultBob.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );
        
        Assert.True(unpackResultBob.Value.Metadata.Encrypted);
        Assert.True(unpackResultBob.Value.Metadata.Authenticated);
        Assert.True(unpackResultBob.Value.Metadata.NonRepudiation);
        Assert.True(unpackResultBob.Value.Metadata.AnonymousSender);
        Assert.False(unpackResultBob.Value.Metadata.ReWrappedInForward);

        var packResultCharlie = await didComm.PackEncrypted(
            PackEncryptedParams.Builder(message, CHARLIE_DID)
                .ProtectSenderId(true)
                .SignFrom(ALICE_DID)
                .From(ALICE_DID)
                .BuildPackEncryptedParams()
        );
        
    
        var forwardCharlie = await routing.UnpackForward(
            packResultCharlie.PackedMessage,
            secretResolver: new Mediator2SecretResolverMock()
        );
    
        var forwardedMsg = JsonUtils.ToJson(forwardCharlie.Value.ForwardMsg.ForwardedMsg);
    
        forwardCharlie = await routing.UnpackForward(
            forwardedMsg,
            secretResolver: new Mediator1SecretResolverMock()
        );
    
        forwardedMsg = JsonUtils.ToJson(forwardCharlie.Value.ForwardMsg.ForwardedMsg);
    
        var unpackResultCharlie =await  didComm.Unpack(
            new UnpackParamsBuilder(forwardedMsg)
                .SecretResolver(new CharlieSecretResolverMock())
                .BuildUnpackParams()
        );
        
        Assert.True(unpackResultCharlie.Value.Metadata.Encrypted);
        Assert.True(unpackResultCharlie.Value.Metadata.Authenticated);
        Assert.True(unpackResultCharlie.Value.Metadata.NonRepudiation);
        Assert.True(unpackResultCharlie.Value.Metadata.AnonymousSender);
        Assert.False(unpackResultCharlie.Value.Metadata.ReWrappedInForward);
    
        //TODO
        message.Should().BeEquivalentTo(unpackResultBob.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResultBob.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResultBob.Value.Message.Body.First().Key);
       
        //TODO
        message.Should().BeEquivalentTo(unpackResultCharlie.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResultCharlie.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResultCharlie.Value.Message.Body.First().Key);
        
        unpackResultBob.Value.Message.To = null;
        unpackResultBob.Value.Metadata.EncryptedTo = null;
        unpackResultBob.Value.Metadata.SignedMessage = null;
        unpackResultBob.Value.Metadata.EncryptedTo = null;
        unpackResultBob.Value.Metadata.SignedMessage = null;
        unpackResultCharlie.Value.Message.To = null;
        unpackResultCharlie.Value.Metadata.EncryptedTo = null;
        unpackResultCharlie.Value.Metadata.SignedMessage = null;
        unpackResultCharlie.Value.Metadata.EncryptedTo = null;
        unpackResultCharlie.Value.Metadata.SignedMessage = null;
        unpackResultBob.Value.Message.Should().BeEquivalentTo(unpackResultCharlie.Value.Message, options => options.Excluding(x => x.Body));
        unpackResultBob.Value.Metadata.Should().BeEquivalentTo(unpackResultCharlie.Value.Metadata);
    }

    [Fact]
    public async Task Test_encrypt_message_with_attachments()
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

        var packResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, BOB_DID).BuildPackEncryptedParams()
        );

        var unpackResult =await  didComm.Unpack(
            new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .BuildUnpackParams()
        );

        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
    }
}