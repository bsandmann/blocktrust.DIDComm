namespace Blocktrust.DIDComm.Tests.CryptoKey;

using Blocktrust.Common.Exceptions;
using Crypto.JWE;
using Crypto.Keys;
using Exceptions;
using FluentAssertions;
using TestData.DIDDoc;
using TestData.Fixtures;
using TestData.Mock;

public class SenderKeySelectorTests
{
    [Fact]
    public async Task Test_find_anon_crypto_keys_by_DID()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var keysResult = await senderKeySelector.FindAnonCryptKeys(JWMFixture.BOB_DID);

        var expected = new List<string>
        {
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        };

        Assert.Equivalent(expected, keysResult.Value.Select(it => it.Id));
    }

    [Fact]
    public async Task Test_find_anon_crypto_keys_by_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var keysResult = await senderKeySelector.FindAnonCryptKeys("did:example:bob#key-x25519-2");

        var expected = new List<string> { "did:example:bob#key-x25519-2" };
        Assert.Equivalent(expected, keysResult.Value.Select(it => it.Id));
    }

    [Fact]
    public async Task Test_find_signing_key_by_DID()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var key = await senderKeySelector.FindSigningKey(JWMFixture.ALICE_DID);

        var expected = "did:example:alice#key-1";
        Assert.Equal(expected, key.Value.Id);
    }

    [Fact]
    public async Task Test_find_signing_key_by_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var key = await senderKeySelector.FindSigningKey("did:example:alice#key-2");

        var expected = "did:example:alice#key-2";
        Assert.Equal(expected, key.Value.Id);
    }

    [Fact]
    public async Task Test_find_auth_crypto_keys_by_DID()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var findAuthCryptKeysResult = await senderKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, JWMFixture.BOB_DID);
        (Key from, List<Key> to) = findAuthCryptKeysResult.Value;

        var expected = (
            "did:example:alice#key-x25519-1",
            new List<string>
            {
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3"
            }
        );

        Assert.Equal(expected.Item1, from.Id);
        Assert.Equivalent(expected.Item2, to.Select(p => p.Id));
    }

    [Fact]
    public async Task Test_find_auth_crypto_keys_by_Alice_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var findAuthCryptKeysResult = await senderKeySelector.FindAuthCryptKeys("did:example:alice#key-x25519-1", JWMFixture.BOB_DID);
        (Key from, List<Key> to) = findAuthCryptKeysResult.Value;

        var expected = (
            "did:example:alice#key-x25519-1",
            new List<string>
            {
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3"
            }
        );

        Assert.Equal(expected.Item1, from.Id);
        Assert.Equivalent(expected.Item2, to.Select(p => p.Id));
    }

    [Fact]
    public async Task Test_find_auth_crypto_keys_by_Bob_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var findAuthCryptKeysResult = await senderKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, "did:example:bob#key-x25519-3");
        (Key from, List<Key> to) = findAuthCryptKeysResult.Value;

        var expected = (
            "did:example:alice#key-x25519-1",
            new List<string>
            {
                "did:example:bob#key-x25519-3"
            }
        );

        Assert.Equal(expected.Item1, from.Id);
        Assert.Equivalent(expected.Item2.First(), to.First().Id);
    }

    [Fact]
    public async Task Test_find_auth_crypto_keys_by_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var findAuthCryptKeysResult = await senderKeySelector.FindAuthCryptKeys("did:example:alice#key-x25519-1", "did:example:bob#key-x25519-3");
        (Key from, List<Key> to) = findAuthCryptKeysResult.Value;

        var expected = (
            "did:example:alice#key-x25519-1",
            new List<string>
            {
                "did:example:bob#key-x25519-3"
            }
        );

        Assert.Equal(expected.Item1, from.Id);
        Assert.Equal(expected.Item2.First(), to.First().Id);
    }

    [Fact]
    public async Task Test_find_second_type_auth_key()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        string expectedSenderKey = "did:example:alice#key-p256-1";
        List<string> expectedRecipientKeys = new List<string>
        {
            "did:example:bob#key-p256-1",
            "did:example:bob#key-p256-2"
        };

        var findAuthCryptKeysResult = await senderKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, "did:example:bob#key-p256-2");
        (Key from, List<Key> to) = findAuthCryptKeysResult.Value;
        //TODO compare: I dont kknow if the id is correct
        Assert.Equal(expectedSenderKey, from.Id);

        var findAuthCryptKeysResult2 = await senderKeySelector.FindAuthCryptKeys("did:example:alice#key-p256-1", JWMFixture.BOB_DID);
        var (_, recipients) = findAuthCryptKeysResult2.Value;
        Assert.Equivalent(expectedRecipientKeys, recipients.Select(it => it.Id));
    }

    [Fact]
    public async Task Test_signing_key_not_found_by_DID()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());

        var result = await senderKeySelector.FindSigningKey(JWMFixture.BOB_DID);
        result.IsSuccess.Should().BeFalse();
        result.Errors.First().Message.Should().Be($"The DID Doc '{JWMFixture.BOB_DID}' does not contain compatible 'authentication' verification methods");
    }

    [Fact]
    public async Task Test_key_not_found_by_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var didUrl = "did:example:alice#key-x25519-3";

        var findSigningKeyResult = await senderKeySelector.FindSigningKey(didUrl);
        findSigningKeyResult.IsSuccess.Should().BeFalse();
        findSigningKeyResult.Errors.First().Message.Should().Be("Unable to find secret for signing of 'did:example:alice#key-x25519-3'");
        
        var findAuthCryptKeysResult = await senderKeySelector.FindAuthCryptKeys(didUrl, "did:example:bob#key-x25519-1");
        findAuthCryptKeysResult.IsSuccess.Should().BeFalse();
        findAuthCryptKeysResult.Errors.First().Message.Should().Be("Unable to find secret of 'did:example:alice#key-x25519-3'");
        
        var findAuthCryptKeysResult2 =  await senderKeySelector.FindAuthCryptKeys(didUrl, JWMFixture.BOB_DID);
        findAuthCryptKeysResult2.IsSuccess.Should().BeFalse();
        findAuthCryptKeysResult2.Errors.First().Message.Should().Be("Unable to find secret of 'did:example:alice#key-x25519-3'");
    }

    [Fact]
    public async Task Test_verification_method_not_found_by_DID_URL()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var expected = "The DID URL 'did:example:bob#key-4' not found in DID Doc 'did:example:bob'";
        var didUrl = "did:example:bob#key-4";

        var exception1 = await Assert.ThrowsAsync<DidUrlNotFoundException>(async () => await senderKeySelector.FindAnonCryptKeys(didUrl));
        Assert.Equal(expected, exception1.Message);
        var exception2 = await Assert.ThrowsAsync<DidUrlNotFoundException>(async () => await senderKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, didUrl));
        Assert.Equal(expected, exception2.Message);
    }

    [Fact]
    public async Task Test_DID_Doc_not_resolved()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var did = JWMFixture.NONA_DID;
        var expected = $"The DID Doc '{did}' not resolved";

        var findSigningKeyResult = await senderKeySelector.FindSigningKey(did);
        findSigningKeyResult.IsSuccess.Should().BeFalse();
        findSigningKeyResult.Errors.First().Message.Should().Be("DID 'did:example:nona' could not be resolved");

        var findAnonCryptKeysResult = await senderKeySelector.FindAnonCryptKeys(did);
        findAnonCryptKeysResult.IsSuccess.Should().BeFalse();
        findAnonCryptKeysResult.Errors.First().Message.Should().Be("DID 'did:example:nona' could not be resolved");
        
        var findAuthCryptKeysResult= await senderKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, did);
        findAuthCryptKeysResult.IsSuccess.Should().BeFalse();
        findAuthCryptKeysResult.Errors.First().Message.Should().Be("DID 'did:example:nona' could not be resolved");
        
        var findAuthCryptKeysResult2 = await senderKeySelector.FindAuthCryptKeys(did, JWMFixture.ALICE_DID);
        findAuthCryptKeysResult2.IsSuccess.Should().BeFalse();
        findAuthCryptKeysResult2.Errors.First().Message.Should().Be("DID 'did:example:nona' could not be resolved");
    }

    [Fact]
    public async Task Test_empty_DID_Doc()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new AliceSecretResolverMock());
        var result1 = await senderKeySelector.FindSigningKey(JWMFixture.ELLIE_DID);
        result1.IsFailed.Should().BeTrue();
        result1.Errors.First().Message.Should().Be("The DID Doc '" + JWMFixture.ELLIE_DID + "' does not contain compatible 'authentication' verification methods");

        var result2 =  await senderKeySelector.FindAnonCryptKeys(JWMFixture.ELLIE_DID);
        result2.IsFailed.Should().BeTrue();
        result2.Errors.First().Message.Should().Be("The DID Doc '" + JWMFixture.ELLIE_DID + "' does not contain compatible 'keyAgreement' verification methods");
        
        var result3 = await senderKeySelector.FindAuthCryptKeys(JWMFixture.ELLIE_DID, JWMFixture.BOB_DID);
        result3.IsFailed.Should().BeTrue();
        result3.Errors.First().Message.Should().Be("The DID Docs '" + JWMFixture.ELLIE_DID + "' and '" + JWMFixture.BOB_DID + "' do not contain compatible 'keyAgreement' verification methods");
        
        var result4 = await senderKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, JWMFixture.ELLIE_DID);
        result4.IsFailed.Should().BeTrue();
        result4.Errors.First().Message.Should().Be("The DID Docs '" + JWMFixture.ALICE_DID + "' and '" + JWMFixture.ELLIE_DID + "' do not contain compatible 'keyAgreement' verification methods");
    }

    [Fact]
    public async Task Test_incompatible_Crypto()
    {
        var senderKeySelector = new SenderKeySelector(new DidDocResolverMock(), new CharlieSecretResolverMock());
        var bobDIDUrl = "did:example:bob#key-p256-1";
        var charlieDIDUrl = "did:example:charlie#key-x25519-1";

        var result1 = await senderKeySelector.FindAuthCryptKeys(JWMFixture.CHARLIE_DID, bobDIDUrl);
        result1.IsFailed.Should().BeTrue();
        result1.Errors.First().Message.Should().Be("The DID Docs '" + JWMFixture.CHARLIE_DID + "' and '" + JWMFixture.BOB_DID + "' do not contain compatible 'keyAgreement' verification methods");

        var result2 =  await senderKeySelector.FindAuthCryptKeys(charlieDIDUrl, bobDIDUrl);
        result2.IsFailed.Should().BeTrue();
        result2.Errors.First().Message.Should().Be("The recipient '" + bobDIDUrl + "' curve is not compatible to 'X25519'");
    }

    [Fact]
    public async Task Test_find_anoncrypt_pack_recipient_public_keys_by_did_unknown_did()
    {
        var keySelector = new SenderKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));
        var result = await keySelector.FindAnonCryptKeys("did:example:unknown");
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("DID 'did:example:unknown' could not be resolved");
    }

    [Fact]
    public async Task Test_find_anoncrypt_pack_recipient_public_keys_by_kid_unknown_did()
    {
        var keySelector = new SenderKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));

        var result =await keySelector.FindAnonCryptKeys("did:example:unknown#key-1");
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("DID 'did:example:unknown' could not be resolved");
    }

    [Fact]
    public async Task Test_find_anoncrypt_pack_recipient_public_keys_by_kid_unknown_kid()
    {
        var keySelector = new SenderKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));

        var result =await keySelector.FindAnonCryptKeys(JWMFixture.BOB_DID + "unknown#key-1");
        result.IsFailed.Should().BeTrue();
        result.Errors.First().Message.Should().Be("DID 'did:example:bobunknown' could not be resolved");
    }

    [Fact]
    public void Test_find_anoncrypt_pack_recipient_public_keys_by_kid_positive()
    {
        var keySelector = new SenderKeySelector(new DidDocResolverMockWithNoSecrets(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));
        DIDDocBob.DID_DOC_BOB_WITH_NO_SECRETS.VerificationMethods.ToList().ForEach(async vm =>
        {
            var res = (await keySelector.FindAnonCryptKeys(vm.Id)).Value.Select(it => it.Jwk).ToList();
            var listOfVM = new List<Jwk> { Key.FromVerificationMethod(vm).Jwk };
            Assert.Equivalent(listOfVM, res);
        });
    }

    [Fact]
    public async Task Test_find_anoncrypt_pack_recipient_public_keys_by_did_positive()
    {
        var keySelector = new SenderKeySelector(new DidDocResolverMockWithNoSecrets(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));

        var expected = TestUtils.GetKeyAgreementMethods(TestUtils.Person.BOB, TestUtils.KeyAgreementCurveType.X25519)
            .Select(it => Key.FromVerificationMethod(it).Jwk).ToList();
        var res = (await keySelector.FindAnonCryptKeys(JWMFixture.BOB_DID)).Value.Select(it => it.Jwk).ToList();

        Assert.Equivalent(expected, res);
    }
}