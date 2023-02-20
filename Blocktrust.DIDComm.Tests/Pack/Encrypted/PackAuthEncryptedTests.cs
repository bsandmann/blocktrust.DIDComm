namespace Blocktrust.DIDComm.Tests.Pack.Encrypted;

using Common.Algorithms;
using Crypto.Keys;
using DIDComm.Utils;
using Exceptions;
using Message.Messages;
using Model.PackEncryptedParamsModels;
using Model.PackEncryptedResultModels;
using Model.UnpackParamsModels;
using Operations;
using TestData.Fixtures;
using TestData.Messages;
using TestData.Mock;

public class PackAuthEncryptedTests
{
    public static IEnumerable<object[]> PackAuthEncryptedTest()
    {
        var signedFromList = TestUtils.GetAuthMethodsInSecrets(TestUtils.Person.ALICE).Select(it => it.Id).ToList();
        signedFromList.Add(JWMFixture.ALICE_DID);
        
        var data = TestUtils.CartesianProduct(
            new List<object>() { JWMFixture.PLAINTEXT_MESSAGE, DIDCommMessages.AttachmentMulti1msg(), DIDCommMessages.AttachmentJsonMsg() },
            new List<object>() { AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW },
            new List<object>() { AnonCryptAlg.XC20P_ECDH_ES_A256KW, AnonCryptAlg.A256GCM_ECDH_ES_A256KW, AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW },
            new List<object>() { TestUtils.KeyAgreementCurveType.X25519, TestUtils.KeyAgreementCurveType.P256, TestUtils.KeyAgreementCurveType.P521, TestUtils.KeyAgreementCurveType.P384 },
            new List<object>() { true, false },
            signedFromList.Select(p => (object)p).ToList()
        ).Select(it => new PackAuthEncryptedTestData(
            (Message)it[0],
            new AuthCryptAlg((string)it[1]),
            new AnonCryptAlg((string)it[2]),
            (TestUtils.KeyAgreementCurveType)it[3],
            (bool)it[4],
            (string)it[5]
        ));
        return data.Select(p => new object[] { p });
    }

    [Theory]
    [MemberData(nameof(PackAuthEncryptedTest))]
    public void TestAuthcryptSenderDIDRecipientDID(PackAuthEncryptedTestData data)
    {
        data.CurveType = TestUtils.KeyAgreementCurveType.X25519;
        CheckAuthcrypt(data, JWMFixture.ALICE_DID, JWMFixture.BOB_DID);
    }
    
    [Theory]
    [MemberData(nameof(PackAuthEncryptedTest))]
    public void TestAuthcryptSenderDIDRecipientKid(PackAuthEncryptedTestData data)
    {
        var toList = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB, TestUtils.KeyAgreementCurveType.X25519).Select(it => it.Id).ToList();
        toList.Add(JWMFixture.BOB_DID);
        foreach (var to in toList)
        {
            data.CurveType = TestUtils.KeyAgreementCurveType.X25519;
            CheckAuthcrypt(data, JWMFixture.ALICE_DID, to);
        }
    }
    
    [Theory]
    [MemberData(nameof(PackAuthEncryptedTest))]
    public void TestAuthcryptSenderKidRecipientDID(PackAuthEncryptedTestData data)
    {
        var fromList = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.ALICE, data.CurveType).Select(x => x.Id).ToList();

        foreach (var from in fromList)
        {
            CheckAuthcrypt(data, from, JWMFixture.BOB_DID);
        }
    }
    
    [Theory]
    [MemberData(nameof(PackAuthEncryptedTest))]
    public void TestAuthcryptSenderKidRecipientKid(PackAuthEncryptedTestData data)
    {
        var fromList = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.ALICE, data.CurveType).Select(x => x.Id).ToList();
        var toList = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB, data.CurveType).Select(x => x.Id).ToList();
    
        foreach (var from in fromList)
        {
            foreach (var to in toList)
            {
                CheckAuthcrypt(data, from, to);
            }
        }
    }

    public void CheckAuthcrypt(PackAuthEncryptedTestData data, string from, string to)
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        PackEncryptedResult packResult = null;
        try
        {
            packResult = didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(data.Msg, to)
                    .From(from)
                    .SignFrom(data.SignedFrom)
                    .ProtectSenderId(data.ProtectSenderId)
                    .EncAlgAuth(data.AuthAlg)
                    .EncAlgAnon(data.AnonAlg)
                    .BuildPackEncryptedParams()
            );
        }
        catch (UnsupportedAlgorithmException e)
        {
            throw e;
        }

        var expectedTo = new List<string> { to };
        if (!DidUtils.IsDidUrl(to))
        {
            expectedTo = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB, data.CurveType).Select(x => x.Id).ToList();
        }

        var expectedFrom = from;
        if (!DidUtils.IsDidUrl(from))
        {
            expectedFrom = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.ALICE)[0].Id;
        }

        var expectedSignFrm = data.SignedFrom != JWMFixture.ALICE_DID ? data.SignedFrom : TestUtils.GetAuthMethodsInSecrets(TestUtils.Person.ALICE)[0].Id;

        Assert.Equal(packResult.FromKid, expectedFrom);
        Assert.Equal(packResult.ToKids, expectedTo);
        Assert.Equal(packResult.SignFromKid, expectedSignFrm);
        Assert.NotNull(packResult.PackedMessage);

        var recipientKeySelector = new RecipientKeySelector(new DidDocResolverMock(), new BobSecretResolverMock());

        var unpackResult = Unpacker.Unpack(
            keySelector: recipientKeySelector,
            param: new UnpackParamsBuilder(packResult.PackedMessage)
                .ExpectDecryptByAllKeys(true)
                .BuildUnpackParams()
        );

        var expectedAnonAlg = data.ProtectSenderId ? data.AnonAlg : null;

        Assert.Equal(unpackResult.Message.ToString(), data.Msg.ToString());
        
        
        Assert.True(
            unpackResult.Metadata.EncAlgAnon?.CryptAlg == expectedAnonAlg?.CryptAlg ||
            unpackResult.Metadata.EncAlgAnon?.CryptAlg == new AnonCryptAlg(AnonCryptAlg.XC20P_ECDH_ES_A256KW).CryptAlg
        );
        Assert.True(
            unpackResult.Metadata.EncAlgAuth?.CryptAlg == data.AuthAlg.CryptAlg ||
            unpackResult.Metadata.EncAlgAuth?.CryptAlg == new AuthCryptAlg(AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW).CryptAlg
        );
        Assert.Equal(unpackResult.Metadata.AnonymousSender, data.ProtectSenderId);
        Assert.True(unpackResult.Metadata.Encrypted);
        Assert.Equal(unpackResult.Metadata.NonRepudiation, data.SignedFrom != "");
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
        Assert.True(unpackResult.Metadata.Authenticated);
    }
}