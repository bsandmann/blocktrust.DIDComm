namespace Blocktrust.DIDComm.Tests.TestData.DIDDoc;

using Blocktrust.Common.Models.DidDoc;
using DIDComm.ProtocolsRouting.Routing;

public class DIDDocMediator2
{
    public static readonly VerificationMethod MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 =
        new VerificationMethod(
            id:  "did:example:mediator2#key-x25519-1",
            controller: "did:example:mediator2#key-x25519-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
            }
        """.Trim()
            }
        );

    public static readonly VerificationMethod MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1 =
        new VerificationMethod(
            id: "did:example:mediator2#key-p256-1",
            controller:"did:example:mediator2#key-p256-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
            }   
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1 =
        new VerificationMethod(
            id: "did:example:mediator2#key-p384-1",
            controller:"did:example:mediator2#key-p384-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
            }
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1 =
        new VerificationMethod(
            id: "did:example:mediator2#key-p521-1",
            controller:"did:example:mediator2#key-p521-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
        {
            "kty": "EC",
            "crv": "P-521",
            "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
            "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
        }
        """.Trim()
            }
        );
    
    DidDoc DID_DOC_MEDIATOR2_SPEC_TEST_VECTORS = new DidDoc
    {
        Did = "did:example:mediator2",
        Authentications = new List<string>
        {
         
        },
        KeyAgreements = new List<string>
        {
            "did:example:mediator2#key-x25519-1",
            "did:example:mediator2#key-p256-1",
            "did:example:mediator2#key-p384-1",
            "did:example:mediator2#key-p521-1",
        },
        Services = new List<Service>
        {
            
        },
        VerificationMethods = new List<VerificationMethod>
        {
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        },
    };

    public static DidDoc DID_DOC_MEDIATOR2 = new DidDoc
    {
        Did =  "did:example:mediator2",
        Authentications = new List<string>
        {
        },
        KeyAgreements = new List<string>
        {
            "did:example:mediator2#key-x25519-1",
            "did:example:mediator2#key-p256-1",
            "did:example:mediator2#key-p384-1",
            "did:example:mediator2#key-p521-1",
        },
        Services = new List<Service>
        {
            new Service
            (
                id : "did:example:123456789abcdefghi#didcomm-1",
                serviceEndpoint : new ServiceEndpoint( uri:"http://example.com/path",
                accept : new List<string>
                {
                    Routing.PROFILE_DIDCOMM_V2,
                    Routing.PROFILE_DIDCOMM_AIP2_ENV_RFC587
                },
                routingKeys : new List<string>
                {
                    "did:example:mediator1#key-x25519-1"
                }
            )) 
        },
        VerificationMethods = new List<VerificationMethod>
        {
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
            MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        },
    };

}