﻿namespace Blocktrust.DIDComm.Tests.TestData.DIDDoc;

using Blocktrust.Common.Models.DidDoc;
using DIDComm.ProtocolsRouting.Routing;

public class DIDDocAlice
{
    public static readonly VerificationMethod ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET =
        new VerificationMethod(
            id: "did:example:alice#key-x25519-not-in-secrets-1",
            controller: "did:example:alice#key-x25519-not-in-secrets-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
            }
        """.Trim()
            }
        );

    public static readonly VerificationMethod ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519 =
        new VerificationMethod(
            id: "did:example:alice#key-x25519-1",
            controller: "did:example:alice#key-x25519-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
            }
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256 =
        new VerificationMethod(
            id: "did:example:alice#key-p256-1",
            controller:"did:example:alice#key-p256-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
            }
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521 =
        new VerificationMethod(
            id:"did:example:alice#key-p521-1",
            controller:"did:example:alice#key-p521-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
            }
        """.Trim()
            }
        );
   
    public static readonly VerificationMethod ALICE_AUTH_METHOD_25519_NOT_IN_SECRET =
        new VerificationMethod(
            id:"did:example:alice#key-not-in-secrets-1",
            controller:"did:example:alice#key-not-in-secrets-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod ALICE_AUTH_METHOD_25519 =
        new VerificationMethod(
            id:"did:example:alice#key-1",
            controller: "did:example:alice#key-1",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod ALICE_AUTH_METHOD_P256 =
        new VerificationMethod(
            id:"did:example:alice#key-2",
            controller:"did:example:alice#key-2",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
            }
        """.Trim()
            }
        );
    
    public static readonly VerificationMethod ALICE_AUTH_METHOD_SECPP256K1 =
        new VerificationMethod(
            id:"did:example:alice#key-3",
            controller:"did:example:alice#key-3",
            type: VerificationMethodType.JsonWebKey2020,
            verificationMaterial: new VerificationMaterial
            {
                Format = VerificationMaterialFormat.Jwk,
                Value = """
            {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
            }
        """.Trim()
            }
        );

    public static DidDoc DID_DOC_ALICE_SPEC_TEST_VECTORS = new DidDoc
    {
        Did = "did:example:alice",
        Authentications = new List<string>
        {
            "did:example:alice#key-1",
            "did:example:alice#key-2",
            "did:example:alice#key-3",
        },
        KeyAgreements = new List<string>
        {
            "did:example:alice#key-x25519-not-in-secrets-1",
            "did:example:alice#key-x25519-1",
            "did:example:alice#key-p256-1",
            "did:example:alice#key-p521-1",
        },
        Services = new List<Service>
        {
            new Service
            (
                id : "did:example:123456789abcdefghi#didcomm-1",
                serviceEndpoint : new ServiceEndpoint(uri: "did:example:mediator1",
                accept : new List<string>
                {
                    Routing.PROFILE_DIDCOMM_V2,
                    Routing.PROFILE_DIDCOMM_AIP2_ENV_RFC587
                },
                routingKeys : new List<string>
                {
                    "did:example:mediator2#key-p521-1"
                }
                )
            )
        },
        VerificationMethods = new List<VerificationMethod>
        {
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
            ALICE_AUTH_METHOD_25519_NOT_IN_SECRET,
            ALICE_AUTH_METHOD_25519,
            ALICE_AUTH_METHOD_P256,
            ALICE_AUTH_METHOD_SECPP256K1,
        },
    };

    public static DidDoc DID_DOC_ALICE_WITH_NO_SECRETS = new DidDoc
    {
        Did = "did:example:alice",
        Authentications = new List<string>
        {
            "did:example:alice#key-not-in-secrets-1",
            "did:example:alice#key-1",
            "did:example:alice#key-2",
            "did:example:alice#key-3",
        },
        KeyAgreements = new List<string>
        {
            "did:example:alice#key-x25519-not-in-secrets-1",
            "did:example:alice#key-x25519-1",
            "did:example:alice#key-p256-1",
            "did:example:alice#key-p521-1",
        },
        Services = new List<Service>
        {
         
        },
        VerificationMethods = new List<VerificationMethod>
        {
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
            ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
            ALICE_AUTH_METHOD_25519_NOT_IN_SECRET,
            ALICE_AUTH_METHOD_25519,
            ALICE_AUTH_METHOD_P256,
            ALICE_AUTH_METHOD_SECPP256K1,
        },
    };
}