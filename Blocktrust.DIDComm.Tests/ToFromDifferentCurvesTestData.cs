namespace Blocktrust.DIDComm.Tests;

public class ToFromDifferentCurvesTestData
{
    public TestUtils.KeyAgreementCurveType CurveTypeSender { get; set; }
    public TestUtils.KeyAgreementCurveType CurveTypeRecipient { get; set; }
    public ToFromDifferentCurvesTestData(TestUtils.KeyAgreementCurveType curveTypeSender, TestUtils.KeyAgreementCurveType curveTypeRecipient)
    {
        this.CurveTypeSender = curveTypeSender;
        this.CurveTypeRecipient = curveTypeRecipient;
    }
}