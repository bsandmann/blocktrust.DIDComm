namespace Blocktrust.DIDComm.Tests.CryptoKey;

using Crypto.Keys;
using Exceptions;
using TestData.Fixtures;
using TestData.Mock;

public class TestRecipientKeySelectorCurves
{
    public static IEnumerable<object[]> TestRecipientKeySelectorDifferentCurves()
    {
        return new List<object[]>()
        {
            new object[] { new DifferentCurveTypesTestData(TestUtils.KeyAgreementCurveType.P256) },
            new object[] { new DifferentCurveTypesTestData(TestUtils.KeyAgreementCurveType.P521) },
            new object[] { new DifferentCurveTypesTestData(TestUtils.KeyAgreementCurveType.P384) },
            new object[] { new DifferentCurveTypesTestData(TestUtils.KeyAgreementCurveType.X25519) },
        };
    }

    [Theory]
    [MemberData(nameof(TestRecipientKeySelectorDifferentCurves))]
    public async Task Test_find_anoncrypt_unpack_recipient_private_keys_positive_multiple_keys(DifferentCurveTypesTestData data)
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));
    
        var secrets = TestUtils.GetKeyAgreementSecrets(TestUtils.Person.BOB, data.CurveType);
        var toKids = secrets.Select(s => s.Kid).ToList();
    
        var res = (await keySelector.FindAnonCryptKeys(toKids)).Select(it => it.Jwk).ToList();
    
        var keySecrets = secrets.Select(s => Key.FromSecret(s).Jwk);
        Assert.Equivalent(keySecrets, res);
    }
    
    [Theory]
    [MemberData(nameof(TestRecipientKeySelectorDifferentCurves))]
    public async Task Test_find_anoncrypt_unpack_recipient_private_keys_all_not_in_secrets(DifferentCurveTypesTestData data)
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));
    
        var notInSecretKids = TestUtils.GetKeyAgreementMethodsNotInSecrets(TestUtils.Person.BOB, data.CurveType).Select(vm => vm.Id).ToList();

        await Assert.ThrowsAsync<SecretNotFoundException>(async () => await keySelector.FindAnonCryptKeys(notInSecretKids));
    }
    
    [Theory]
    [MemberData(nameof(TestRecipientKeySelectorDifferentCurves))]
    public async Task test_find_anoncrypt_unpack_recipient_private_keys_known_and_unknown(DifferentCurveTypesTestData data)
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));
    
        var secrets = TestUtils.GetKeyAgreementSecrets(TestUtils.Person.BOB, data.CurveType);
        var validKids = secrets.Select(s => s.Kid);
        var toKids = new List<string> { "did:example:unknown1#key-1", $"{JWMFixture.BOB_DID}#unknown-key-2" }.Concat(validKids).ToList();
    
        var res = (await keySelector.FindAnonCryptKeys(toKids)).Select(it => it.Jwk).ToList();
    
        var keySecrets = secrets.Select(s => Key.FromSecret(s).Jwk);
        Assert.Equivalent(keySecrets, res);
    }
    
    [Theory]
    [MemberData(nameof(TestRecipientKeySelectorDifferentCurves))]
    public async Task test_find_anoncrypt_unpack_recipient_private_keys_in_secrets_and_not(DifferentCurveTypesTestData data)
    {
        var keySelector = new RecipientKeySelector(new DidDocResolverMock(), TestUtils.GetSecretsResolver(TestUtils.Person.BOB));
    
        var secrets = TestUtils.GetKeyAgreementSecrets(TestUtils.Person.BOB, data.CurveType);
        var validKids = secrets.Select(s => s.Kid);
        var notInSecretKids = TestUtils.GetKeyAgreementMethodsNotInSecrets(TestUtils.Person.BOB, data.CurveType).Select(s => s.Id);
        var kids = notInSecretKids.Concat(validKids).ToList();
    
        var res = (await keySelector.FindAnonCryptKeys(kids)).Select(it => it.Jwk).ToList();
    
        var keySecrets = secrets.Select(s => Key.FromSecret(s).Jwk).ToList();
        Assert.Equivalent(res, keySecrets);
    }
}