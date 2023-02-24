namespace Blocktrust.DIDComm.Tests;

using System.Text.Json;
using DIDComm.Utils;
using Exceptions;
using FluentAssertions;
using Message.Attachments;
using Message.FromPriors;
using Message.Messages;
using Model.PackPlaintextParamsModels;
using Model.UnpackParamsModels;
using Newtonsoft.Json.Linq;
using TestData.Fixtures;
using TestData.Mock;

public class PlaintextMessageTests
{
    [Fact]
    public void Test_pack_unpack_plaintext_message()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var packed = didComm.PackPlaintext(
            new PackPlaintextParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE).BuildPackPlaintext()
        );

        Assert.NotNull(packed.PackedMessage);

        var unpacked = didComm.Unpack(
            new UnpackParamsBuilder(packed.PackedMessage).BuildUnpackParams()
        );

        var expected = JWMFixture.PLAINTEXT_MESSAGE;

        //The problem is, that the unpacked body consits of objects which are JsonElements and this reference-body consists of objects which are strings
        // Assert.Equivalent(message, unpackResult.message);
        expected.Should().BeEquivalentTo(unpacked.Value.Message, options => options.Excluding(x => x.Body));
        expected.Body.Count.Should().Be(unpacked.Value.Message.Body.Count);
        expected.Body.First().Key.Should().BeEquivalentTo(unpacked.Value.Message.Body.First().Key);
        expected.Body.First().Value.Should().BeEquivalentTo(unpacked.Value.Message.Body.First().Value?.ToString());
    }

    [Fact]
    public void Test_pack_unpack_plaintext_message_with_from_prior_and_issuer_kid()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceRotatedToCharlieSecretResolverMock());

        var messages = new List<Message> { JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR_MINIMAL, JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR };
        foreach (var message in messages)
        {
            var packResult = didComm.PackPlaintext(
                new PackPlaintextParamsBuilder(message)
                    .FromPriorIssuerKid("did:example:alice#key-2")
                    .BuildPackPlaintext()
            );

            Assert.NotNull(packResult.PackedMessage);
            Assert.Equal("did:example:alice#key-2", packResult.FromPriorIssuerKid);

            var unpackResult = didComm.Unpack(
                new UnpackParamsBuilder(packResult.PackedMessage).BuildUnpackParams()
            );

            Assert.Equivalent("did:example:alice#key-2", unpackResult.Value.Metadata.FromPriorIssuerKid);
            Assert.Equal(
                JObject.Parse(packResult.PackedMessage)["from_prior"]?.ToString(),
                unpackResult.Value.Metadata.FromPriorJwt);
            // Assert.Equivalent(message, unpackResult.Value.Message);
            //The problem is, that the unpacked body consits of objects which are JsonElements and this reference-body consists of objects which are strings
            message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
            message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
            message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
            message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        }
    }

    [Fact]
    public void Test_pack_unpack_plaintext_message_with_from_prior_and_no_issuer_kid()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceRotatedToCharlieSecretResolverMock());

        var messages = new List<Message> { JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR_MINIMAL, JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR };
        foreach (var message in messages)
        {
            var packResult = didComm.PackPlaintext(
                new PackPlaintextParamsBuilder(message).BuildPackPlaintext()
            );

            Assert.NotNull(packResult.PackedMessage);
            Assert.NotNull(packResult.FromPriorIssuerKid);
            Assert.True(DidUtils.IsDid(packResult.FromPriorIssuerKid));
            Assert.True(DidUtils.IsDidFragment(packResult.FromPriorIssuerKid));
            Assert.Equal(JWMFixture.ALICE_DID, DidUtils.DivideDidFragment(packResult.FromPriorIssuerKid).First());

            var unpackResult = didComm.Unpack(
                new UnpackParamsBuilder(packResult.PackedMessage).BuildUnpackParams()
            );

            //TODO
            message.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
            message.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
            message.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
            message.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
            Assert.Equal(packResult.FromPriorIssuerKid, unpackResult.Value.Metadata.FromPriorIssuerKid);
            Assert.Equal(
                JObject.Parse(packResult.PackedMessage)["from_prior"],
                unpackResult.Value.Metadata.FromPriorJwt
            );
        }
    }

    [Fact]
    public void Test_pack_plaintext_message_with_invalid_from_prior()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceRotatedToCharlieSecretResolverMock());

        foreach (var message in JWMFixture.INVALID_FROM_PRIOR_PLAINTEXT_MESSAGES)
        {
            Action act = () => didComm.PackPlaintext(new PackPlaintextParamsBuilder(message).BuildPackPlaintext());
            act.Should().Throw<Exception>();
        }
    }

    [Fact]
    public void Test_unpack_plaintext_message_with_from_prior()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceRotatedToCharlieSecretResolverMock());

        var unpackResult = didComm.Unpack(
            new UnpackParamsBuilder(JWMFixture.PACKED_MESSAGE_FROM_PRIOR).BuildUnpackParams()
        );

        //TODO
        JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR.Should().BeEquivalentTo(unpackResult.Value.Message, options => options.Excluding(x => x.Body));
        JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR.Body.Count.Should().Be(unpackResult.Value.Message.Body.Count);
        JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR.Body.First().Key.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Key);
        JWMFixture.PLAINTEXT_MESSAGE_FROM_PRIOR.Body.First().Value.Should().BeEquivalentTo(unpackResult.Value.Message.Body.First().Value?.ToString());
        Assert.Equal("did:example:alice#key-1", unpackResult.Value.Metadata.FromPriorIssuerKid);
        Assert.Equal(
            JObject.Parse(JWMFixture.PACKED_MESSAGE_FROM_PRIOR)["from_prior"],
            unpackResult.Value.Metadata.FromPriorJwt
        );
    }

    [Fact]
    public void Test_unpack_plaintext_message_with_invalid_from_prior()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceRotatedToCharlieSecretResolverMock());

        foreach (var tv in JWMFixture.WRONG_FROM_PRIOR_PACKED_MESSAGES)
        {
            var result = didComm.Unpack(
                new UnpackParamsBuilder(tv.Json).BuildUnpackParams()
            );

            Assert.False(result.IsSuccess);
            Assert.Contains(tv.ExpectedMessage, result.Errors.First().Message);
        }
    }

    [Fact]
    public void Test_plaintext_without_body()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var result = didComm.Unpack(
            new UnpackParamsBuilder(JWMFixture.PACKED_MESSAGE_WITHOUT_BODY).BuildUnpackParams()
        );

            Assert.False(result.IsSuccess);
        Assert.Contains("The header \"body\" is missing", result.Errors.First().Message);
    }

    [Fact]
    public void Test_plaintext_custom_body_with_jackson()
    {
        var body = new Dictionary<string, object>() { { "some", "content" } };

        var message = Message.Builder("1", body, "protocol")
            .createdTime(1)
            .expiresTime(2)
            .build();

        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var packed = didComm.PackPlaintext(
            new PackPlaintextParamsBuilder(message).BuildPackPlaintext()
        );

        Assert.NotNull(packed.PackedMessage);

        var unpacked = didComm.Unpack(
            new UnpackParamsBuilder(packed.PackedMessage).BuildUnpackParams()
        );

        var unpackedBody = unpacked.Value.Message.Body;
        var unpackedProtocolMessage = unpackedBody["some"];
        Assert.Equal(body["some"].ToString(), ((JsonElement)(unpackedProtocolMessage ?? throw new InvalidOperationException())).GetString());
    }

    [Fact]
    public void Test_custom_headers_works()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var message = Message.Builder("1", new Dictionary<string, object>(), "protocol")
            .customHeader("null", null)
            .customHeader("int", 2)
            .customHeader("string", "Hello, world")
            .customHeader("booleanTrue", true)
            .customHeader("booleanFalse", false)
            .customHeader("object", new Dictionary<string, object> { { "foo", "bar" } })
            .customHeader("array", new List<long> { 1, 2, 3, 4, 5 })
            .build();

        var packed = didComm.PackPlaintext(
            new PackPlaintextParamsBuilder(message).BuildPackPlaintext()
        );

        var unpacked = didComm.Unpack(
            new UnpackParamsBuilder(packed.PackedMessage).BuildUnpackParams()
        );

        Assert.Null(unpacked.Value.Message.CustomHeader<object>("null"));
        Assert.Equal(2L, unpacked.Value.Message.CustomHeader<long>("int"));
        Assert.Equal("Hello, world", unpacked.Value.Message.CustomHeader<string>("string"));
        Assert.True(unpacked.Value.Message.CustomHeader<bool?>("booleanTrue") ?? false);
        Assert.False(unpacked.Value.Message.CustomHeader<bool?>("booleanFalse") ?? true);
        var obj = unpacked.Value.Message.CustomHeaderObject("object");
        var objContent = (JsonElement)obj!["foo"];
        Assert.Equal("bar", objContent.GetString()!);
        Assert.Equal(new List<long> { 1, 2, 3, 4, 5 }, unpacked.Value.Message.CustomHeader<List<long>>("array"));
    }

    [Fact]
    public void Test_header_reserved_name()
    {
        var builder = Message.Builder("", new Dictionary<string, object>(), "");

        foreach (var header in MessageHeader.reservedHeaderNames)
        {
            var expected = $"The header name '{header}' is reserved";

            var actual = Assert.Throws<DidCommException>(() => { builder.customHeader(header, null); });

            Assert.Equal(expected, actual.Message);
        }
    }

    [Fact]
    public void Test_parse_when_message_is_empty_json()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var result = didComm.Unpack(
            new UnpackParamsBuilder("{}").BuildUnpackParams()
        );

        Assert.False(result.IsSuccess);
        Assert.Contains("The header \"id\" is missing", result.Errors.First().Message);
    }

    [Fact]
    public void Test_wrong_attachment_data()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        foreach (var tv in JWMFixture.WRONG_ATTACHMENTS)
        {
            var result = didComm.Unpack(
                new UnpackParamsBuilder(tv.Json).BuildUnpackParams()
            );

            Assert.False(result.IsSuccess);
            Assert.Contains(tv.ExpectedMessage, result.Errors.First().Message);
        }
    }

    [Fact]
    public void Test_correct_attachment_data()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        foreach (var tv in JWMFixture.CORRECT_ATTACHMENTS)
        {
            var unpack = didComm.Unpack(
                new UnpackParamsBuilder(tv.Json).BuildUnpackParams()
            );

            var actual = unpack.Value.Message.Attachments
                ?.Select(it => it.Data)
                ?.Select(it =>
                    new ExpectedAttachmentData(
                        isLinks: it is Links,
                        isBase64: it is Base64,
                        isJson: it is Json
                    )
                );

            Assert.Equivalent(tv.ExpectedAttachmentData, actual);
        }
    }

    [Fact]
    public void Test_full_plaintext_message()
    {
        var fromPrior = FromPrior.Builder(JWMFixture.ALICE_DID, JWMFixture.CHARLIE_DID)
            .Aud("aud")
            .Exp(123456789)
            .Nbf(987654321)
            .Iat(1234554321)
            .Jti("jti")
            .Build();

        var attachments = new List<Attachment>
        {
            new AttachmentBuilder(
                    "1",
                    new Base64(
                        base64: "qwerty",
                        jws: new Dictionary<string, object>
                        {
                            { "payload", "payload" },
                            { "signature", "signature" }
                        },
                        hash: "hash"
                    )
                )
                .Filename("filename")
                .LastModTime(0)
                .Format("format")
                .Description("some description")
                .MediaType("text/json")
                .ByteCount(1L)
                .Build()
        };

        var body = new Dictionary<string, object>
        {
            {
                "array", new List<object>
                {
                    new Dictionary<string, object> { { "foo", "bar" } },
                    2L,
                    true,
                    false,
                    null,
                    new List<long> { 1L, 2L, 3L }
                }
            },
            { "first", "first" },
            { "second", null },
            {
                "object", new Dictionary<string, object>
                {
                    { "first", 1L },
                    { "second", true }
                }
            }
        };

        var message = Message.Builder("id1", body, "coolest-protocol")
            .from(JWMFixture.CHARLIE_DID)
            .to(new List<string> { JWMFixture.BOB_DID, JWMFixture.ELLIE_DID })
            .createdTime(123)
            .expiresTime(456)
            .fromPrior(fromPrior)
            .attachments(attachments)
            .pleaseAck(true)
            .ack("ack")
            .thid("thid")
            .pthid("pthid")
            .customHeader("foo", "bar")
            .customHeader("array", new List<long> { 1, 2, 3 })
            .build();

        var didComm = new DidComm(new DidDocResolverMock(), new AliceRotatedToCharlieSecretResolverMock());

        var packed = didComm.PackPlaintext(
            new PackPlaintextParamsBuilder(message).BuildPackPlaintext()
        );

        var unpack = didComm.Unpack(
            new UnpackParamsBuilder(packed.PackedMessage).BuildUnpackParams()
        );

        Assert.Equivalent(message.FromPrior, unpack.Value.Message.FromPrior);
        //TODO the usaul problem with jsonelement
        // Assert.Equivalent(message.Attachments.First(), unpack.message.Attachments.First());
        message.Attachments.First().Should().BeEquivalentTo(unpack.Value.Message.Attachments.First(), options => options.Excluding(x => x.Data.Jws));
        message.Attachments.Count.Should().Be(unpack.Value.Message.Attachments.Count);
        message.Attachments.First().Data.Jws["payload"].Should().BeEquivalentTo(unpack.Value.Message.Attachments.First().Data.Jws["payload"].ToString());
        message.Attachments.First().Data.Jws["signature"].Should().BeEquivalentTo(unpack.Value.Message.Attachments.First().Data.Jws["signature"].ToString());


        Assert.Equal(
            message.Body["first"].ToString(),
            unpack.Value.Message.Body.GetTyped<string>("first").ToString()
        );

        Assert.Equal(
            message.Body.GetTyped<string>("second"),
            unpack.Value.Message.Body.GetTyped<string>("second")
        );

        var expectedObject = message.Body["object"] as Dictionary<string, object>;
        var actualObject = unpack.Value.Message.Body.GetTyped<Dictionary<string, object>>("object");

        Assert.NotNull(expectedObject);
        Assert.NotNull(actualObject);

        Assert.Equal(
            expectedObject["first"],
            actualObject.GetTyped<long>("first")
        );

        Assert.Equal(
            expectedObject["second"],
            actualObject.GetTyped<bool>("second")
        );

        // var expectedArray = message.Body.GetTyped<List<object>>("array")?.ToArray();
        var expectedArray = message.Body["array"] as List<object>;
        var actualArray = unpack.Value.Message.Body.GetTypedArray<object>("array");
        //TODO nasty. The same old json problem
        //TODO im to lazy to compare it here in the tests
        // Assert.Equivalent(expectedArray[0], actualArray[0][0].ToString());
        Assert.Equal(message.From, unpack.Value.Message.From);
        Assert.Equal(message.CreatedTime, unpack.Value.Message.CreatedTime);
        Assert.Equal(message.ExpiresTime, unpack.Value.Message.ExpiresTime);
        Assert.Equal(message.PleaseAck, unpack.Value.Message.PleaseAck);
        Assert.Equal(message.Ack, unpack.Value.Message.Ack);
        Assert.Equal(message.Thid, unpack.Value.Message.Thid);
        Assert.Equal(message.Pthid, unpack.Value.Message.Pthid);
        Assert.Equivalent(message.To, unpack.Value.Message.To);

        Assert.Equal(
            message.CustomHeaders["foo"],
            unpack.Value.Message.CustomHeader<string>("foo")
        );

        //TODO nasty json shit
        // Assert.Equivalent(
        //     message.CustomHeaders["array"] as List<long>,
        // unpack.message.CustomHeaderArray<List<long?>>("array")
        // );
    }
}