namespace Blocktrust.DIDComm.Tests.CryptoKey;

using Blocktrust.Common.Exceptions;
using Crypto.JWE;
using Crypto.Keys;
using Exceptions;
using TestData.Fixtures;
using TestData.Mock;

public class RecipientKeySelectorTests
{
    [Fact]
    public void Test_find_verification_key()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());
        var expected = "did:example:alice#key-2";
        var key = recipientKeySelector.FindVerificationKey(expected);
        Assert.Equal(expected, key.Id);
    }

    [Fact]
    public void Test_find_anon_crypto_keys()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());

        var expected = new List<string>
        {
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        };

        var keys = recipientKeySelector.FindAnonCryptKeys(expected);
        Assert.Equal(expected, keys.Select(x => x.Id).ToList());
    }

    [Fact]
    public void Test_find_second_anon_crypto_key()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());

        var recipient = new List<string>
        {
            "did:example:bob#key-x25519-4",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-5"
        };

        var expected = new List<string>
        {
            "did:example:bob#key-x25519-2"
        };

        var keys = recipientKeySelector.FindAnonCryptKeys(recipient);
        Assert.Equal(expected, keys.Select(x => x.Id).ToList());
    }

    [Fact]
    public void Test_find_auth_crypto_keys()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());

        var sender = "did:example:alice#key-x25519-1";
        var recipient = new List<string>
        {
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
            "did:example:bob#key-x25519-3"
        };

        var (from, to) = recipientKeySelector.FindAuthCryptKeys(sender, recipient);

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
        Assert.Equal(expected.Item2, to.Select(x => x.Id).ToList());
    }

    [Fact]
    public void Test_DID_is_passed_to_methods()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());

        var exception1 = Assert.Throws<Exception>(() => recipientKeySelector.FindVerificationKey(JWMFixture.ALICE_DID));
        Assert.Equal("'DID URL' is expected as a signature verification key. Got: did:example:alice", exception1.Message);

        var exception2 = Assert.Throws<Exception>(() => recipientKeySelector.FindAuthCryptKeys(JWMFixture.ALICE_DID, new List<string> { JWMFixture.BOB_DID }));
        Assert.Equal("'DID URL' is expected as a sender key. Got: did:example:alice", exception2.Message);

        var exception3 = Assert.Throws<Exception>(() => recipientKeySelector.FindAnonCryptKeys(new List<string> { JWMFixture.BOB_DID }));
        Assert.Equal("'DID URL' is expected as a recipient key. Got: did:example:bob", exception3.Message);
    }

    [Fact]
    public void Test_key_not_found()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());
        var didUrl = "did:example:bob#key-x25519-4";
        var expected = $"The Secret '{didUrl}' not found";

        var exception1 = Assert.Throws<SecretNotFoundException>(() => recipientKeySelector.FindAnonCryptKeys(new List<string> { didUrl }).ToList());
        Assert.Equal(expected, exception1.Message);

        var exception2 = Assert.Throws<SecretNotFoundException>(() => recipientKeySelector.FindAuthCryptKeys("did:example:alice#key-x25519-1", new List<string> { didUrl }).Item2.ToList());
        Assert.Equal(expected, exception2.Message);
    }

    [Fact]
    public void Test_verification_method_not_found()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());
        var expected = "The DID URL 'did:example:bob#key-4' not found in DID Doc 'did:example:bob'";
        var didUrl = "did:example:bob#key-4";


        var exception1 = Assert.Throws<DidUrlNotFoundException>(() => recipientKeySelector.FindAuthCryptKeys(didUrl, new List<string> { didUrl }));
        Assert.Equal(expected, exception1.Message);

        var exception2 = Assert.Throws<DidUrlNotFoundException>(() => recipientKeySelector.FindVerificationKey(didUrl));
        Assert.Equal(expected, exception2.Message);
    }

    [Fact]
    public void Test_DID_Doc_not_resolved()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());
        var did = JWMFixture.NONA_DID;
        var didUrl = $"{did}#key-1";
        var expected = $"The DID URL '{didUrl}' not found in DID Doc '{did}'";

        var exception1 = Assert.Throws<DidUrlNotFoundException>(() => recipientKeySelector.FindVerificationKey(didUrl));
        Assert.Equal(expected, exception1.Message);

        var exception2 = Assert.Throws<DidUrlNotFoundException>(() => recipientKeySelector.FindAuthCryptKeys(didUrl, new List<string>()));
        Assert.Equal(expected, exception2.Message);
    }

    [Fact]
    public void Test_empty_DID_Doc()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());
        var didUrl = $"{JWMFixture.ELLIE_DID}#key-2";
        var expected = $"The DID URL '{didUrl}' not found in DID Doc 'did:example:ellie'";

        var exception1 = Assert.Throws<DidUrlNotFoundException>(() => recipientKeySelector.FindVerificationKey(didUrl));
        Assert.Equal(expected, exception1.Message);

        var exception2 = Assert.Throws<DidUrlNotFoundException>(() => recipientKeySelector.FindAuthCryptKeys(didUrl, new List<string>()));
        Assert.Equal(expected, exception2.Message);
    }

    [Fact]
    public void Test_incompatible_Crypto()
    {
        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());
        var bobDIDUrl = "did:example:bob#key-p256-1";
        var charlieDIDUrl = "did:example:charlie#key-x25519-1";

        var exception1 = Assert.Throws<IncompatibleCryptoException>(() => recipientKeySelector.FindAuthCryptKeys(charlieDIDUrl, new List<string> { bobDIDUrl }).Item2.ToList());
        Assert.Equal("The recipient '" + bobDIDUrl + "' curve is not compatible to 'X25519'", exception1.Message);
    }

    [Fact]
    public void Test_find_anoncrypt_unpack_recipient_private_keys_positive_single_key()
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));

        foreach (var vm in TestUtils.GetKeyAgreementSecrets(TestUtils.Person.BOB))
        {
            var res = keySelector.FindAnonCryptKeys(new List<string> { vm.Kid }).Select(it => it.Jwk).ToList();
            var expected = new List<Jwk>() { Key.FromSecret(vm).Jwk }; 
            
            Assert.Equivalent(res, expected); 
        }
    }

    [Fact]
    public void Test_find_anoncrypt_unpack_recipient_private_keys_all_kids_unknown()
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));

        Assert.Throws<SecretNotFoundException>(() => keySelector.FindAnonCryptKeys(new List<string> { JWMFixture.BOB_DID + "#unknown-key-1", JWMFixture.BOB_DID + "#unknown-key-2" }).ToList());
    }

    [Fact]
    public void Test_find_anoncrypt_unpack_recipient_private_keys_different_curves()
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));

        var secrets = TestUtils.GetKeyAgreementSecrets(TestUtils.Person.BOB).Select(s => Key.FromSecret(s)).ToList();
        var kids = secrets.Select(s => s.Id).ToList();
        var expected = secrets.Select(it => it.Jwk).ToList();
        
        var res = keySelector.FindAnonCryptKeys(kids).Select(it => it.Jwk).ToList(); 

        Assert.Equivalent(expected, res);
    }
}