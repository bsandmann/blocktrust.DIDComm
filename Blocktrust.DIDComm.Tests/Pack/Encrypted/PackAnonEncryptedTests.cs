namespace Blocktrust.DIDComm.Tests.Pack.Encrypted;

using Common.Algorithms;
using Exceptions;
using Message.Messages;
using Model.PackEncryptedParamsModels;
using Model.PackEncryptedResultModels;
using Model.UnpackParamsModels;
using TestData.Fixtures;
using TestData.Messages;
using TestData.Mock;

public class PackAnonEncryptedTests
{
    public static IEnumerable<object[]> PackAnonEncryptedTest()
    {
        var toList = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB).Select(it => it.Id).ToList();
        toList.Add(JWMFixture.BOB_DID);
        var signedFromList = TestUtils.GetAuthMethodsInSecrets(TestUtils.Person.ALICE).Select(it => it.Id).ToList();
        signedFromList.Add(JWMFixture.ALICE_DID);

        var data = TestUtils.CartesianProduct(
            new List<object> { JWMFixture.PLAINTEXT_MESSAGE, DIDCommMessages.AttachmentMulti1msg(), DIDCommMessages.AttachmentJsonMsg() },
            new List<object> { AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW, AnonCryptAlg.A256GCM_ECDH_ES_A256KW, AnonCryptAlg.XC20P_ECDH_ES_A256KW },
            //todo modifier
            toList.Select(p => (object)p).ToList(),
            signedFromList.Select(p => (object)p).ToList(),
            new List<object> { true, false }
        ).Select(it => new PackAnonEncryptedTestData(
            (Message)it[0],
            new AnonCryptAlg((string)it[1]),
            (string)it[2],
            (string)it[3],
            (bool)it[4]
        ));

        return data.Select(p => new object[] { p });
    }

    [Theory]
    [MemberData(nameof(PackAnonEncryptedTest))]
    public async void TestAnoncrypt(PackAnonEncryptedTestData data)
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        PackEncryptedResult packResult;
        try
        {
            packResult = (await didComm.PackEncrypted(new PackEncryptedParamsBuilder(
                    message: data.Msg,
                    to: data.To)
                .SignFrom(data.SignedFrom)
                .ProtectSenderId(data.ProtectSenderId)
                .BuildPackEncryptedParams())).Value;
        }
        catch (UnsupportedAlgorithmException e)
        {
            throw e;
        }
    
        var expectedTo = new List<string> { data.To };
        if (data.To == JWMFixture.BOB_DID)
        {
            expectedTo = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB, TestUtils.KeyAgreementCurveType.X25519).Select(it => it.Id).ToList();
        }
    
        var expectedSignFrm = data.SignedFrom != JWMFixture.ALICE_DID ? data.SignedFrom : TestUtils.GetAuthMethodsInSecrets(TestUtils.Person.ALICE)[0].Id;
    
    
        Assert.Null(packResult.FromKid);
        Assert.Equal(packResult.ToKids, expectedTo);
        Assert.Equal(packResult.SignFromKid, expectedSignFrm);
        Assert.NotNull(packResult.PackedMessage);
    
        var didCommUnpack = new DidComm(new DidDocResolverMock(), new BobSecretResolverMock());
        var unpackResult =await  didCommUnpack.Unpack(new UnpackParamsBuilder(
            packedMessage: packResult.PackedMessage).ExpectDecryptByAllKeys(true).BuildUnpackParams());
    
        Assert.Equal(unpackResult.Value.Message.ToString(), data.Msg.ToString());
        Assert.True(
            unpackResult.Value.Metadata.EncAlgAnon?.CryptAlg == data.Alg.CryptAlg ||
            unpackResult.Value.Metadata.EncAlgAnon?.CryptAlg == new AnonCryptAlg(AnonCryptAlg.XC20P_ECDH_ES_A256KW).CryptAlg
        );
    
        Assert.Null(unpackResult.Value.Metadata.EncAlgAuth);
        Assert.True(unpackResult.Value.Metadata.AnonymousSender);
        Assert.True(unpackResult.Value.Metadata.Encrypted);
        Assert.Equal(unpackResult.Value.Metadata.NonRepudiation, data.SignedFrom != "");
        Assert.Equal(unpackResult.Value.Metadata.Authenticated, data.SignedFrom != "");
        Assert.False(unpackResult.Value.Metadata.ReWrappedInForward);
    }
}