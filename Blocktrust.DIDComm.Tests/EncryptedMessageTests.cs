namespace Blocktrust.DIDComm.Tests;

using Blocktrust.Common.Exceptions;
using Common.Algorithms;
using DIDComm.ProtocolsRouting.Routing;
using DIDComm.Utils;
using Exceptions;
using FluentAssertions;
using Model.PackEncryptedParamsModels;
using Model.UnpackParamsModels;
using TestData.Fixtures;
using TestData.Mock;

public class EncryptedMessageTests
{
    [Fact]
    public async Task Test_encrypted_message_test_vectors()
    {
        foreach (var tv in JWEFixture.TEST_VECTORS)
        {
            var didComm = new DidComm(new DidDocResolverMock(), new BobSecretResolverMock());
            var unpacked = await didComm.Unpack(
                new UnpackParamsBuilder(tv.message)
                    .ExpectDecryptByAllKeys(true)
                    .BuildUnpackParams()
            );

            JWMFixture.PLAINTEXT_MESSAGE.Should().BeEquivalentTo(unpacked.Value.Message, options => options.Excluding(x => x.Body));
            //TODO extend to test to also check the body in detail
            JWMFixture.PLAINTEXT_MESSAGE.Body.Count.Should().Be(unpacked.Value.Message.Body.Count);
            JWMFixture.PLAINTEXT_MESSAGE.Body.First().Key.Should().BeEquivalentTo(unpacked.Value.Message.Body.First().Key);

            Assert.Equal(tv.expectedMetadata.Encrypted, unpacked.Value.Metadata.Encrypted);
            Assert.Equal(tv.expectedMetadata.Authenticated, unpacked.Value.Metadata.Authenticated);
            Assert.Equal(tv.expectedMetadata.AnonymousSender, unpacked.Value.Metadata.AnonymousSender);
            Assert.Equal(tv.expectedMetadata.NonRepudiation, unpacked.Value.Metadata.NonRepudiation);

            Assert.Equivalent(tv.expectedMetadata.EncAlgAnon, unpacked.Value.Metadata.EncAlgAnon);
            Assert.Equivalent(tv.expectedMetadata.EncAlgAuth, unpacked.Value.Metadata.EncAlgAuth);

            Assert.Equal(tv.expectedMetadata.EncryptedFrom, unpacked.Value.Metadata.EncryptedFrom);
            Assert.Equivalent(tv.expectedMetadata.EncryptedTo, unpacked.Value.Metadata.EncryptedTo);

            Assert.Equal(tv.expectedMetadata.SignAlg, unpacked.Value.Metadata.SignAlg);
            Assert.Equal(tv.expectedMetadata.SignFrom, unpacked.Value.Metadata.SignFrom);
            var expectedSignedMessage = tv.expectedMetadata.SignedMessage != null;
            var actualSignedMessage = unpacked.Value.Metadata.SignedMessage != null;
            Assert.Equal(expectedSignedMessage, actualSignedMessage);
        }
    }

    [Fact]
    public async Task Test_unsupported_exception_es256k_jdk15()
    {
        var testVectors = JWEFixture.TEST_VECTORS.Where(it => it.expectedMetadata.SignAlg == SignAlg.Es256K);
        foreach (var tv in testVectors)
        {
            var didComm = new DidComm(new DidDocResolverMock(), new BobSecretResolverMock());
            await Assert.ThrowsAsync<UnsupportedAlgorithmException>(async () => await didComm.Unpack(
                new UnpackParamsBuilder(tv.message)
                    .ExpectDecryptByAllKeys(true)
                    .BuildUnpackParams()
            ));
        }
    }

    [Fact]
    public async Task Test_decrypt_message_for_part_of_the_keys()
    {
        var routing = new Routing(new DidDocResolverMock(), new AliceSecretResolverMock());
        var message = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        message.To = new List<string> { JWMFixture.CHARLIE_DID };
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var packed = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(message, JWMFixture.CHARLIE_DID)
                .From(JWMFixture.ALICE_DID)
                .BuildPackEncryptedParams()
        );

        // TODO make focused on initial subject (without forward)
        // CHARLIE's first mediator (MEDIATOR2)
        var forwardCharlie = await routing.UnpackForward(
            packed.Value.PackedMessage,
            secretResolver: new Mediator2SecretResolverMock()
        );

        var forwardedMsg = forwardCharlie.Value.ForwardMsg.ForwardedMsg.ToJsonString();

        // CHARLIE's second mediator (MEDIATOR1)
        forwardCharlie = await routing.UnpackForward(
            forwardedMsg,
            secretResolver: new Mediator1SecretResolverMock()
        );

        forwardedMsg = forwardCharlie.Value.ForwardMsg.ForwardedMsg.ToJsonString();

        // CHARLIE
        var unpacked = await didComm.Unpack(
            new UnpackParamsBuilder(forwardedMsg)
                .SecretResolver(new CharlieSecretResolverMock())
                .ExpectDecryptByAllKeys(true)
                .BuildUnpackParams()
        );

        var expectedKids = new List<string>
        {
            "did:example:charlie#key-x25519-1",
            "did:example:charlie#key-x25519-3"
        };

        Assert.Equal(expectedKids, unpacked.Value.Metadata.EncryptedTo);
    }

    [Fact]
    public async Task Test_decrypt_with_message_with_damaged_keys_by_all_keys()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new BobSecretResolverMock());
        var expected = "Decrypt is failed";

        var result = await didComm.Unpack(
            new UnpackParamsBuilder(JWEFixture.BOB_DAMAGED_MESSAGE)
                .ExpectDecryptByAllKeys(true)
                .BuildUnpackParams()
        );

        result.IsFailed.Should().BeTrue();
        Assert.Contains(expected, result.Errors.First().Message);
    }

    [Fact]
    public async Task Test_decrypt_with_message_with_damaged_keys_by_one_key()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new BobSecretResolverMock());
        var expected = new List<string> { "did:example:bob#key-x25519-2" };

        var unpack = await didComm.Unpack(
            new UnpackParamsBuilder(JWEFixture.BOB_DAMAGED_MESSAGE)
                .BuildUnpackParams()
        );

        Assert.Equivalent(expected, unpack.Value.Metadata.EncryptedTo);
    }

    [Fact]
    public async Task Test_decrypt_negative_test_vectors()
    {
        foreach (var tv in JWEFixture.NEGATIVE_TEST_VECTORS)
        {
            var didComm = new DidComm(new DidDocResolverMock(), new BobSecretResolverMock());


            var result = await didComm.Unpack(tv.unpackParams);
            result.IsFailed.Should().BeTrue();
            result.Errors.First().Message.Should().Contain($"{tv.expectedMessage}");
        }
    }

    [Fact]
    public async Task Test_from_is_not_a_did_or_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMockWithNoSecrets(), new AliceSecretResolverMock());

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                    .From("not-a-did")
                    .BuildPackEncryptedParams()
            )
        );
    }

    [Fact]
    public async Task Test_to_is_not_a_did_or_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, "not-a-did")
                    .BuildPackEncryptedParams()
            )
        );
    }

    [Fact]
    public async Task Test_sign_frm_is_not_a_did_or_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                    .From(JWMFixture.ALICE_DID)
                    .SignFrom("not-a-did")
                    .BuildPackEncryptedParams()
            )
        );
    }

    [Fact]
    public async Task Test_from_differs_from_msg_from()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.From = JWMFixture.CHARLIE_DID;

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                    .From(JWMFixture.ALICE_DID)
                    .BuildPackEncryptedParams()
            )
        );
    }

    [Fact]
    public async Task Test_to_differs_from_msg_to()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.To = new List<string> { JWMFixture.CHARLIE_DID };

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                    .From(JWMFixture.ALICE_DID)
                    .BuildPackEncryptedParams()
            )
        );
    }

    [Fact]
    public async Task Test_to_present_in_msg_to()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.To = new List<string> { JWMFixture.CHARLIE_DID, JWMFixture.BOB_DID };

        await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                .From(JWMFixture.ALICE_DID)
                .BuildPackEncryptedParams()
        );
    }

    [Fact]
    public async Task Test_from_is_not_a_did_or_did_url_in_msg()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.From = "not-a-did";

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                    .From("not-a-did")
                    .BuildPackEncryptedParams()
            )
        );
    }

    [Fact]
    public async Task Test_to_is_not_a_did_or_did_url_in_msg()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.To = new List<string> { "not-a-did" };

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
        {
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(msg, "not-a-did")
                    .From(JWMFixture.ALICE_DID)
                    .BuildPackEncryptedParams()
            );
        });
    }

    [Fact]
    public async Task Test_sign_from_differs_from_msg_from_positive()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceNewSecretResolverMock());

        await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                .From(JWMFixture.ALICE_DID)
                .SignFrom(JWMFixture.CHARLIE_DID)
                .BuildPackEncryptedParams()
        );
    }

    [Fact]
    public async Task Test_from_unknown_did()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.From = "did:example:unknown";

        var result = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                .From("did:example:unknown")
                .BuildPackEncryptedParams()
        );
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("DID 'did:example:unknown' could not be resolved");
    }

    [Fact]
    public async Task Test_from_unknown_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var result = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                .From(JWMFixture.ALICE_DID + "#unknown-key")
                .BuildPackEncryptedParams()
        );
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("Unable to find secret of 'did:example:alice#unknown-key'");
    }

    [Fact]
    public async Task Test_to_unknown_did()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.To = new List<string> { "did:example:unknown" };

        var result = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(msg, "did:example:unknown")
                .From(JWMFixture.ALICE_DID)
                .BuildPackEncryptedParams()
        );
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("DID 'did:example:unknown' could not be resolved");
    }

    [Fact]
    public async Task Test_to_unknown_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        await Assert.ThrowsAsync<DidUrlNotFoundException>(async () =>
        {
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID + "#unknown-key")
                    .From(JWMFixture.ALICE_DID)
                    .BuildPackEncryptedParams()
            );
        });
    }

    [Fact]
    public async Task Test_signFrom_unknown_did()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var packResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                .From(JWMFixture.ALICE_DID)
                .SignFrom("did:example:unknown")
                .BuildPackEncryptedParams()
        );
        packResult.IsFailed.Should().BeTrue();
        packResult.Errors.First().Message.Should().Be("DID 'did:example:unknown' could not be resolved");
    }

    [Fact]
    public async Task Test_signFrom_unknown_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                .From(JWMFixture.ALICE_DID)
                .SignFrom(JWMFixture.ALICE_DID + "#unknown-key")
                .BuildPackEncryptedParams()
        );
    }

    [Fact]
    public async Task Test_from_not_in_secrets()
    {
        var didComm = new DidComm(new DidDocResolverMockWithNoSecrets(), new AliceSecretResolverMock());
        var frm = TestUtils.GetKeyAgreementMethodsNotInSecrets(TestUtils.Person.ALICE)[0].Id;
        var result = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                .From(frm)
                .BuildPackEncryptedParams()
        );
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("Unable to find secret of 'did:example:alice#key-x25519-not-in-secrets-1'");
    }

    [Fact]
    public async Task Test_signFrom_not_in_secrets()
    {
        var didComm = new DidComm(new DidDocResolverMockWithNoSecrets(), new AliceSecretResolverMock());

        var frm = TestUtils.GetKeyAgreementMethodsNotInSecrets(TestUtils.Person.ALICE)[0].Id;
        var packEncryptedResult = await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, JWMFixture.BOB_DID)
                .From(JWMFixture.ALICE_DID)
                .SignFrom(frm)
                .BuildPackEncryptedParams()
        );
        packEncryptedResult.IsFailed.Should().BeTrue();
        packEncryptedResult.Errors.First().Message.Should().Be("Unable to find secret for signing of 'did:example:alice#key-x25519-not-in-secrets-1'");
    }

    [Fact]
    public async Task Test_to_not_in_secrets_positive()
    {
        var didComm = new DidComm(new DidDocResolverMockWithNoSecrets(), new AliceSecretResolverMock());
        var to = TestUtils.GetKeyAgreementMethodsNotInSecrets(TestUtils.Person.BOB)[0].Id;
        await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, to)
                .From(JWMFixture.ALICE_DID)
                .BuildPackEncryptedParams()
        );
    }

    [Fact]
    public async Task Test_from_param_is_did_from_msg_is_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.From = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.ALICE)[0].Id;
        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
        {
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                    .From(JWMFixture.ALICE_DID)
                    .BuildPackEncryptedParams()
            );
        });
    }

    [Fact]
    public async Task Test_to_param_is_url_to_msg_is_did_positive()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.To = new List<string> { JWMFixture.ALICE_DID, JWMFixture.BOB_DID };
        await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(msg, TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB)[0].Id)
                .BuildPackEncryptedParams()
        );
    }

    [Fact]
    public async Task Test_from_param_is_url_from_msg_is_did_positive()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy();
        msg.From = JWMFixture.ALICE_DID;
        await didComm.PackEncrypted(
            new PackEncryptedParamsBuilder(msg, JWMFixture.BOB_DID)
                .From(TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.ALICE)[0].Id)
                .BuildPackEncryptedParams()
        );
    }
}