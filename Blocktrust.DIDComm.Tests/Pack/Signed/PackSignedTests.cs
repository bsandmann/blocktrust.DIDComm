namespace Blocktrust.DIDComm.Tests.Pack.Signed;

using Exceptions;
using Message.Messages;
using Model.PackSignedParamsModels;
using Model.PackSignedResultModels;
using Model.UnpackParamsModels;
using TestData.Fixtures;
using TestData.Messages;
using TestData.Mock;

public class PackSignedTests
{
    public static IEnumerable<object[]> PackSignedTest()
    {
        var signedFromList = TestUtils.GetAuthMethodsInSecrets(TestUtils.Person.ALICE).Select(a => a.Id).ToList();
        signedFromList.Add(JWMFixture.ALICE_DID);

        var data = TestUtils.CartesianProduct(
            new List<object> { JWMFixture.PLAINTEXT_MESSAGE, DIDCommMessages.AttachmentMulti1msg(), DIDCommMessages.AttachmentJsonMsg() },
            signedFromList.Select(p => (object)p).ToList()
        ).Select(it => new PackSignedTestData(
            (Message)it[0],
            (string)it[1]
        )).ToList();
        return data.Select(p => new object[] { p });
    }

    [Theory]
    [MemberData(nameof(PackSignedTest))]
    public void TestSigned(PackSignedTestData data)
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        PackSignedResult packResult;
        try
        {
            packResult = didComm.PackSigned(
                new PackSignedParamsBuilder(message: data.Msg, signFrom: data.SignedFrom).BuildPackSginedParams()
            );
        }
        catch (UnsupportedAlgorithmException e)
        {
            throw e;
        }

        var expectedSignFrm = TestUtils.GetAuthMethodsInSecrets(TestUtils.Person.ALICE)[0].Id;
        if (data.SignedFrom != JWMFixture.ALICE_DID)
        {
            expectedSignFrm = data.SignedFrom;
        }

        Assert.Equal(packResult.SignFromKid, expectedSignFrm);
        Assert.NotNull(packResult.PackedMessage);

        var unpackResult = didComm.Unpack(
            param: new UnpackParamsBuilder(packResult.PackedMessage)
                .SecretResolver(new BobSecretResolverMock())
                .ExpectDecryptByAllKeys(true)
                .BuildUnpackParams()
        );

        Assert.Equal(unpackResult.Message.ToString(), data.Msg.ToString());
        Assert.True(unpackResult.Metadata.NonRepudiation);
        Assert.True(unpackResult.Metadata.Authenticated);
        Assert.Null(unpackResult.Metadata.EncAlgAnon);
        Assert.Null(unpackResult.Metadata.EncAlgAuth);
        Assert.False(unpackResult.Metadata.AnonymousSender);
        Assert.False(unpackResult.Metadata.Encrypted);
        Assert.False(unpackResult.Metadata.ReWrappedInForward);
    }
}