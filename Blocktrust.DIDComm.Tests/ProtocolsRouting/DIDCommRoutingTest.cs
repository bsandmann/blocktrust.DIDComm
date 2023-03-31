namespace Blocktrust.DIDComm.Tests.ProtocolsRouting;

using DIDComm.ProtocolsRouting.ForwardMessages;
using DIDComm.ProtocolsRouting.Routing;
using DIDComm.Utils;
using FluentAssertions;
using Message.Messages;
using Model.PackEncryptedParamsModels;
using Model.UnpackParamsModels;
using TestData.Mock;

public class DIDCommRoutingTest
{
    private const string ALICE_DID = "did:example:alice";
    private const string BOB_DID = "did:example:bob";
    private const string CHARLIE_DID = "did:example:charlie";
    private const string MEDIATOR2_DID = "did:example:mediator2";
    private static readonly DidDocResolverMockWithNoSecrets DidDocResolver = new DidDocResolverMockWithNoSecrets();
    private static readonly AliceSecretResolverMock AliceSecretResolver = new AliceSecretResolverMock();
    private readonly BobSecretResolverMock _bobSecretResolver = new BobSecretResolverMock();
    private readonly CharlieSecretResolverMock _charlieSecretResolver = new CharlieSecretResolverMock();
    private readonly Mediator1SecretResolverMock _mediator1SecretResolver = new Mediator1SecretResolverMock();
    private readonly Mediator2SecretResolverMock _mediator2SecretResolver = new Mediator2SecretResolverMock();
    private readonly DidComm _didComm = new DidComm(DidDocResolver, AliceSecretResolver);
    private readonly Routing _routing = new Routing(DidDocResolver, AliceSecretResolver);

     [Fact]
     public async Task Test_single_mediator()
     {
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
     
         var packResult = await _didComm.PackEncrypted(
             PackEncryptedParams.Builder(message, BOB_DID)
                 .From(ALICE_DID)
                 .BuildPackEncryptedParams()
         );
     
         // BOB MEDIATOR
         // TODO ??? why do we need the recipients selector (question to 'unpack' actually)
         var forwardBob = await _routing.UnpackForward(
             packResult.Value.PackedMessage,
             secretResolver: _mediator1SecretResolver
         );
     
         var forwardedMsg = JsonUtils.ToJson(forwardBob.Value.ForwardMsg.ForwardedMsg);
     
         // BOB
         var unpackResult =await  _didComm.Unpack(
             new UnpackParamsBuilder(forwardedMsg)
                 .SecretResolver(_bobSecretResolver)
                 .BuildUnpackParams()
         );
     
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
     public async Task Test_multiple_mediators()
     {
         var message = Message.Builder(
                 id: "1234567890",
                 body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                 type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
             )
             .from(ALICE_DID)
             .to(new List<string> { CHARLIE_DID })
             .createdTime(1516269022)
             .expiresTime(1516385931)
             .build();
     
         var packResult = await _didComm.PackEncrypted(
             PackEncryptedParams.Builder(message, CHARLIE_DID)
                 .From(ALICE_DID)
                 .BuildPackEncryptedParams()
         );
     
         // TODO make focused on initial subject (without forward)
         // CHARLIE's first mediator (MEDIATOR2)
         var forwardCharlie = await _routing.UnpackForward(
             packResult.Value.PackedMessage,
             secretResolver: _mediator2SecretResolver
         );
         
         var forwardedMsg = JsonUtils.ToJson(forwardCharlie.Value.ForwardMsg.ForwardedMsg);
         
         // CHARLIE's second mediator (MEDIATOR1)
         forwardCharlie = await _routing.UnpackForward(
             forwardedMsg,
             secretResolver: _mediator1SecretResolver
         );
         
         forwardedMsg = JsonUtils.ToJson(forwardCharlie.Value.ForwardMsg.ForwardedMsg);
         
         // CHARLIE
         var unpackResult =await  _didComm.Unpack(
             new UnpackParamsBuilder(forwardedMsg)
                 .SecretResolver(_charlieSecretResolver)
                 .ExpectDecryptByAllKeys(true)
                 .BuildUnpackParams()
         );
         
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
     public async Task Test_single_mediator_re_wrap_to_unknown()
     {
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
     
         var packResult = await _didComm.PackEncrypted(
             PackEncryptedParams.Builder(message, BOB_DID)
                 .From(ALICE_DID)
                 .BuildPackEncryptedParams()
         );
     
         // BOB's MEDIATOR
         var forwardBob = await _routing.UnpackForward(
             packResult.Value.PackedMessage,
             secretResolver: _mediator1SecretResolver
         );
     
         var nextTo = forwardBob.Value.ForwardMsg.ForwardNext;
         Assert.NotNull(nextTo);
     
         // re-wrap to unexpected mediator (MEDIATOR2 here)
         var wrapResult = await _routing.WrapInForward(
             forwardBob.Value.ForwardMsg.ForwardedMsg,
             nextTo,
             routingKeys: new List<string> { MEDIATOR2_DID },
             headers: new Dictionary<string, object> { { "somefield", 99999 } }
         );
     
         Assert.NotNull(wrapResult);
     
         // MEDIATOR2
         forwardBob = await _routing.UnpackForward(
             wrapResult.MsgEncrypted.PackedMessage,
             secretResolver: _mediator2SecretResolver
         );
     
         var forwardedMsg = JsonUtils.ToJson(forwardBob.Value.ForwardMsg.ForwardedMsg);
     
         // BOB
         var unpackResult =await  _didComm.Unpack(
             new UnpackParamsBuilder(forwardedMsg)
                 .SecretResolver(_bobSecretResolver)
                 .BuildUnpackParams()
         );
     
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
     public async Task Test_single_mediator_re_wrap_anoncrypt_to_receiver()
     {
         var message = Message.Builder(
                 id: "1234567890",
                 body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                 type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
             )
             .to(new List<string> { BOB_DID })
             .createdTime(1516269022)
             .expiresTime(1516385931)
             .build();
     
         var packResult = await _didComm.PackEncrypted(
             PackEncryptedParams.Builder(message, BOB_DID).BuildPackEncryptedParams()
         );
     
         // BOB's MEDIATOR
         var forwardBob = await _routing.UnpackForward(
             packResult.Value.PackedMessage,
             secretResolver: _mediator1SecretResolver
         );
     
         var nextTo = forwardBob.Value.ForwardMsg.ForwardNext;
         Assert.NotNull(nextTo);
     
         // re-wrap to the receiver
         var wrapResult = await _routing.WrapInForward(
             forwardBob.Value.ForwardMsg.ForwardedMsg,
             nextTo,
             routingKeys: new List<string> { nextTo },
             headers: new Dictionary<string, object> { { "somefield", 99999 } }
         );
     
         Assert.NotNull(wrapResult);
     
         // BOB
         var unpackResult =await  _didComm.Unpack(
             new UnpackParamsBuilder(wrapResult.MsgEncrypted.PackedMessage)
                 .SecretResolver(_bobSecretResolver)
                 .UnwrapReWrappingForward(true)
                 .BuildUnpackParams()
         );
     
         message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
         message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
         message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
         message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
         
         // FIXME here first anon for forward is mixed with inner anon for initial message
         //       in the same metadata
         Assert.True(unpackResult.Value.Metadata.Encrypted);
         Assert.False(unpackResult.Value.Metadata.Authenticated);
         Assert.False(unpackResult.Value.Metadata.NonRepudiation);
         Assert.True(unpackResult.Value.Metadata.AnonymousSender);
         Assert.True(unpackResult.Value.Metadata.ReWrappedInForward);
     }

     [Fact]
     public async Task Test_single_mediator_re_wrap_authcrypt_to_receiver()
     {
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
    
         var packResult = await _didComm.PackEncrypted(
             PackEncryptedParams.Builder(message, BOB_DID)
                 .From(ALICE_DID)
                 .BuildPackEncryptedParams()
         );
    
         // BOB's MEDIATOR
         var forwardBob = await _routing.UnpackForward(
             packResult.Value.PackedMessage,
             secretResolver: _mediator1SecretResolver
         );
    
         var nextTo = forwardBob.Value.ForwardMsg.ForwardNext;
         Assert.NotNull(nextTo);
    
         // re-wrap to the receiver
         var wrapResult = await _routing.WrapInForward(
             forwardBob.Value.ForwardMsg.ForwardedMsg,
             nextTo,
             routingKeys: new List<string> { nextTo },
             headers: new Dictionary<string, object> { { "somefield", 99999 } }
         );
    
         Assert.NotNull(wrapResult);
    
         // BOB
         var unpackResult =await  _didComm.Unpack(
             new UnpackParamsBuilder(wrapResult.MsgEncrypted.PackedMessage)
                 .SecretResolver(_bobSecretResolver)
                 .UnwrapReWrappingForward(true)
                 .BuildUnpackParams()
         );
    
         message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
         message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
         message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
         message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
         // FIXME here first anon for forward is mixed with inner auth for initial message
         //       in the same metadata
         Assert.True(unpackResult.Value.Metadata.Encrypted);
         Assert.True(unpackResult.Value.Metadata.Authenticated);
         Assert.False(unpackResult.Value.Metadata.NonRepudiation);
         Assert.True(unpackResult.Value.Metadata.AnonymousSender);
         Assert.True(unpackResult.Value.Metadata.ReWrappedInForward);
     }

    [Fact]
    public async Task Test_unwrap_re_wrapping_forward_mode_for_no_re_wrapping()
    {
        var message = Message.Builder(
                id: "1234567890",
                body: new Dictionary<string, object> { { "messagespecificattribute", "and its value" } },
                type: "http://example.com/protocols/lets_do_lunch/1.0/proposal"
            )
            .to(new List<string> { BOB_DID })
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build();
        var packResult = await _didComm.PackEncrypted(
            PackEncryptedParams.Builder(message, BOB_DID).BuildPackEncryptedParams()
        );
    
        // BOB's MEDIATOR
        var unpackResultAtMediator =await  _didComm.Unpack(
            new UnpackParamsBuilder(packResult.Value.PackedMessage)
                .SecretResolver(_mediator1SecretResolver)
                .UnwrapReWrappingForward(true)
                .BuildUnpackParams()
        );
    
        var forwardMessage = ForwardMessage.FromMessage(unpackResultAtMediator.Value.Message);
        Assert.NotNull(forwardMessage);
        Assert.Equal(BOB_DID, forwardMessage.ForwardNext);
    
        Assert.True(unpackResultAtMediator.Value.Metadata.Encrypted);
        Assert.False(unpackResultAtMediator.Value.Metadata.Authenticated);
        Assert.False(unpackResultAtMediator.Value.Metadata.NonRepudiation);
        Assert.True(unpackResultAtMediator.Value.Metadata.AnonymousSender);
        Assert.False(unpackResultAtMediator.Value.Metadata.ReWrappedInForward);
    
        // BOB
        var unpackResult =await  _didComm.Unpack(
            new UnpackParamsBuilder(JsonUtils.ToJson(forwardMessage.ForwardedMsg))
                .SecretResolver(_bobSecretResolver)
                .UnwrapReWrappingForward(true)
                .BuildUnpackParams()
        );
    
        message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
    
        Assert.True(unpackResult.Value.Metadata.Encrypted);
        Assert.False(unpackResult.Value.Metadata.Authenticated);
        Assert.False(unpackResult.Value.Metadata.NonRepudiation);
        Assert.True(unpackResult.Value.Metadata.AnonymousSender);
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }
}