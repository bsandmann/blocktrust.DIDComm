namespace Blocktrust.DIDComm.Tests;

using Exceptions;
using FluentAssertions;
using Model.PackEncryptedParamsModels;
using TestData.Fixtures;
using TestData.Mock;

public class TestToFromDifferentCurves
{
    public static IEnumerable<object[]> ToFromDifferentCurvesData()
    {
        return new[]
        {
            new object[] { new ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType.P256, TestUtils.KeyAgreementCurveType.P256) },
            new object[] { new ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType.P256, TestUtils.KeyAgreementCurveType.P521) },
            new object[] { new ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType.P256, TestUtils.KeyAgreementCurveType.X25519) },
            new object[] { new ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType.P521, TestUtils.KeyAgreementCurveType.P521) },
            new object[] { new ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType.P521, TestUtils.KeyAgreementCurveType.X25519) },
            new object[] { new ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType.X25519, TestUtils.KeyAgreementCurveType.X25519) }
        };
    }

    [Theory]
    [MemberData(nameof(ToFromDifferentCurvesData))]
    public async Task TestToFromDifferentCurve(ToFromDifferentCurvesTestData data)
    {
        if (data.CurveTypeRecipient == data.CurveTypeSender) return;

        var didComm = new DidComm(new DidDocResolverMock(), new AliceSecretResolverMock());
        var fromKid = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.ALICE, data.CurveTypeSender)[0].Id;
        var toKid = TestUtils.GetKeyAgreementMethodsInSecrets(TestUtils.Person.BOB, data.CurveTypeRecipient)[0].Id;
        var result =
            await didComm.PackEncrypted(
                new PackEncryptedParamsBuilder(JWMFixture.PLAINTEXT_MESSAGE, toKid)
                    .From(fromKid)
                    .BuildPackEncryptedParams()
            );
        result.IsFailed.Should().BeTrue();
    }
}