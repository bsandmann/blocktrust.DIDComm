namespace Blocktrust.DIDComm.Tests.TestData.Mock;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Secrets;

public class Mediator2SecretResolverMock : SecretResolverInMemoryMock
{
    private static List<Secret> secrets = new List<Secret>()
    {
        new Secret(
            kid: "did:example:mediator2#key-x25519-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial()
            {
                format = VerificationMaterialFormat.Jwk,
                value = """
                    {
                        "kty": "OKP",
                        "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                        "crv": "X25519",
                        "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
                    }
                """
            }
        ),
        new Secret(
            kid: "did:example:mediator2#key-p256-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial()
            {
                format = VerificationMaterialFormat.Jwk,
                value = """
                        {
                            "kty": "EC",
                            "d": "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
                            "crv": "P-256",
                            "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                            "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
                        }
                    """
            }
        ),
        new Secret
        (
            kid: "did:example:mediator2#key-p384-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                format = VerificationMaterialFormat.Jwk,
                value = """
                        {
                            "kty": "EC",
                            "d": "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
                            "crv": "P-384",
                            "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                            "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
                        }
                    """
            }),
        new Secret
        (
            kid: "did:example:mediator2#key-p521-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                format = VerificationMaterialFormat.Jwk,
                value = """
                        {
                            "kty": "EC",
                            "d": "ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk",
                            "crv": "P-521",
                            "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                            "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
                        }
                    """
            }),
    };

    private SecretResolverInMemory _secretResolverInMemory = new SecretResolverInMemory(secrets);

    public List<Secret> GetSecrets()
    {
        return secrets;
    }

    public List<String> GetSecretKids()
    {
        return secrets.Select(secret => secret.Kid).ToList();
    }

    public Task<Secret?> FindKey(String kid)
    {
        return _secretResolverInMemory.FindKey(kid);
    }

    public Task<HashSet<String>> FindKeys(List<String> kids)
    {
        return _secretResolverInMemory.FindKeys(kids);
    }

    public Task AddKey(string kid, Secret secret)
    {
        throw new NotImplementedException();
    }
}