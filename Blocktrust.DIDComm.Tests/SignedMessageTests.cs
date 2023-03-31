namespace Blocktrust.DIDComm.Tests;

using Crypto.JWS;
using Exceptions;
using Model.PackSignedParamsModels;
using Model.UnpackParamsModels;
using TestData.Fixtures;
using TestData.Mock;
using JsonSerializer = System.Text.Json.JsonSerializer;

public class SignedMessageTests
{
    [Fact]
    public async Task Test_signed_message_test_vectors()
    {
    
        foreach (var test in JWSFixture.TEST_VECTORS)
        {
            var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
    
            var packed = await didComm.PackSigned(
                new PackSignedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, test.from).BuildPackSginedParams()
            );
    
            var unpacked = await didComm.Unpack(
                new UnpackParamsBuilder(packed.Value.PackedMessage).BuildUnpackParams()
            );
    
            //TODO unclear if correctly converted
            var expectedDictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(test.expected);
            var expected = JwsObject.Parse(expectedDictionary);
            var signedDictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(packed.Value.PackedMessage);
            var signed = JwsObject.Parse(signedDictionary);
            
            //TODO reactivate this test
            // Assert.Equal(expected.JwsTokenSignatures.First().Header.ToString(), signed.JwsTokenSignatures.First().Header.ToString());
            
            //TODO very much unclear if correctly converted
            Assert.Equal(
                JWMFixture.PLAINTEXT_MESSAGE.ToString(),
                unpacked.Value.Message.ToString()
            );
            
            Assert.Equal(false, unpacked.Value.Metadata.Encrypted);
            Assert.Equal(true, unpacked.Value.Metadata.Authenticated);
            Assert.Equal(true, unpacked.Value.Metadata.NonRepudiation);
            Assert.Equal(false, unpacked.Value.Metadata.AnonymousSender);
            Assert.Equal(test.expectedMetadata.SignFrom, unpacked.Value.Metadata.SignFrom);
            Assert.Equal(test.expectedMetadata.SignAlg, unpacked.Value.Metadata.SignAlg);
        }
    }


    [Fact]
    public async Task Test_from_is_not_a_did_or_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
        {
           await didComm.PackSigned(
                new PackSignedParamsBuilder(
                    JWMFixture.PLAINTEXT_MESSAGE,
                    signFrom: "not-a-did"
                ).BuildPackSginedParams()
            );
        });
    }

    [Fact]
    public async Task Test_from_unknown_did()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        await Assert.ThrowsAsync<DidCommIllegalArgumentException>(async () =>
        {
            await didComm.PackSigned(
                new PackSignedParamsBuilder(
                    JWMFixture.PLAINTEXT_MESSAGE,
                    signFrom: "did:example:unknown"
                ).BuildPackSginedParams()
            );
        });
    }

    [Fact]
    public async Task Test_from_unknown_did_url()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());

        await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
        {
          await  didComm.PackSigned(
                new PackSignedParamsBuilder(
                    JWMFixture.PLAINTEXT_MESSAGE,
                    signFrom: JWMFixture.ALICE_DID + "#unknown-key"
                ).BuildPackSginedParams()
            );
        });
    }

    [Fact]
    public async Task Test_from_not_in_secrets()
    {
        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var frm = TestUtils.GetAuthMethodsNotInSecrets(TestUtils.Person.ALICE)[0].Id;
        await Assert.ThrowsAsync<SecretNotFoundException>(async () =>
        {
          await  didComm.PackSigned(
                new PackSignedParamsBuilder(
                    JWMFixture.PLAINTEXT_MESSAGE,
                    signFrom: frm
                ).BuildPackSginedParams()
            );
        });
    }
}