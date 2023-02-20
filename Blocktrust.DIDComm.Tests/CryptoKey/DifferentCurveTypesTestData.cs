namespace Blocktrust.DIDComm.Tests.CryptoKey;

public class DifferentCurveTypesTestData
{
    public TestUtils.KeyAgreementCurveType CurveType { get; set; }

    public DifferentCurveTypesTestData(TestUtils.KeyAgreementCurveType curveType)
    {
        CurveType = curveType;
    }

}