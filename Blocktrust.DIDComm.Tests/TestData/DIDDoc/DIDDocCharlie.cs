namespace Blocktrust.DIDComm.Tests.TestData.DIDDoc;

using Blocktrust.Common.Models.DidDoc;
using DIDComm.ProtocolsRouting.Routing;

public class DIDDocCharlie
{
    public static readonly VerificationMethod CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 =
        new VerificationMethod(
            id: "did:example:charlie#key-x25519-1",
            controller: "did:example:charlie#key-x25519-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
            }
            """.Trim()
            }
        );

    public static readonly VerificationMethod CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_2 =
        new VerificationMethod(
            id: "did:example:charlie#key-x25519-2",
            controller: "did:example:charlie#key-x25519-2",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                                }
        """.Trim()
            }
        );

    public static readonly VerificationMethod CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_3 =
        new VerificationMethod(
            id: "did:example:charlie#key-x25519-3",
            controller: "did:example:charlie#key-x25519-3",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
                                {
                                   "kty":"OKP",
                                   "crv":"X25519",
                                   "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                                }
        """.Trim()
            }
        );

    public static readonly VerificationMethod CHARLIE_AUTH_METHOD_25519 =
        new VerificationMethod(
            id: "did:example:charlie#key-1",
            controller:"did:example:charlie#key-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"
            }
            """.Trim()
            }
        );


    public static DidDoc DID_DOC_CHARLIE = new DidDoc
    {
        Did = "did:example:charlie",
        Authentications = new List<string>
        {
            "did:example:charlie#key-1"
        },
        KeyAgreements = new List<string>
        {
            "did:example:charlie#key-x25519-1",
            "did:example:charlie#key-x25519-2",
            "did:example:charlie#key-x25519-3",
        },
        Services = new List<Service>
        {
            new Service
            (
                id : "did:example:123456789abcdefghi#didcomm-1",
                serviceEndpoint :"did:example:mediator2",
                accept : new List<string>
                {
                    Routing.PROFILE_DIDCOMM_V2,
                    Routing.PROFILE_DIDCOMM_AIP2_ENV_RFC587
                },
                routingKeys : new List<string>
                {
                    "did:example:mediator1#key-x25519-1"
                }
            )
        },
        VerificationMethods = new List<VerificationMethod>
        {
            CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
            CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
            CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
            CHARLIE_AUTH_METHOD_25519,
        },
    };
    
}