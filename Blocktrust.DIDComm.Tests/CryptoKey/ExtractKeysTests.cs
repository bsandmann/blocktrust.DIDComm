namespace Blocktrust.DIDComm.Tests.CryptoKey;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Crypto;
using Crypto.Keys;

public class ExtractKeysTests
{
     [Fact]
     public void Test_extract_OKP_key_from_JsonWebKey2020_verification_method()
     {
         var key = Key.FromVerificationMethod(
             new VerificationMethod
             (
                 id: "did:example:alice#key-x25519-1",
                 type: VerificationMethodType.JsonWebKey2020,
                 verificationMaterial: new VerificationMaterial
                 (
                     format: VerificationMaterialFormat.Jwk,
                     value: @"
                         {
                             ""kty"": ""OKP"",
                             ""crv"": ""X25519"",
                             ""x"": ""avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs""
                         }"
                 ),
                 controller: "did:example:alice#key-x25519-1"
             )
         );
    
         Assert.Equal("did:example:alice#key-x25519-1", key.Id);
         Assert.Equal(Curve.X25519, key.Curve);
         Assert.Equivalent(
             new Dictionary<string, object>
             {
                 { "kty", "OKP" },
                 { "crv", "X25519" },
                 { "x", "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs" },
             },
             new Dictionary<string, object>
             {
                 { "kty", key.Jwk.Kty },
                 { "crv", key.Jwk.Crv },
                 { "x", key.Jwk.X },
             }
         );
     }

    [Fact]
    public void Test_extract_OKP_key_from_JsonWebKey2020_secret()
    {
        var key = Key.FromSecret(
            new Secret
            (
                kid: "did:example:alice#key-ed25519-2",
                type: VerificationMethodType.JsonWebKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Jwk,
                    value: """
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                            "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY"
                        }
                    """
                )
            )
        );
        Assert.Equal("did:example:alice#key-ed25519-2", key.Id);
        Assert.Equal(Curve.Ed25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "Ed25519" },
                { "x", "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww" },
                { "d", "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY" },
            },
            new Dictionary<string, object>
            {
                { "kty", key.Jwk.Kty },
                { "crv", key.Jwk.Crv },
                { "x", key.Jwk.X },
                { "d", key.Jwk.D },
            }
        );
    }

    [Fact]
    public void Test_extract_EC_key_from_JsonWebKey2020_verification_method()
    {
        var key = Key.FromVerificationMethod(
            new VerificationMethod
            (
                id: "did:example:alice#key-p256-1",
                type: VerificationMethodType.JsonWebKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Jwk,
                    value: @"
                        {
                            ""kty"": ""EC"",
                            ""crv"": ""P-256"",
                            ""x"": ""L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE"",
                            ""y"": ""SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo""
                        }"
                ),
                controller: "did:example:alice#key-p256-1"
            )
        );

        Assert.Equal("did:example:alice#key-p256-1", key.Id);
        Assert.Equal(Curve.P256, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "EC" },
                { "crv", "P-256" },
                { "x", "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE" },
                { "y", "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo" },
            },
            key.Jwk.ToDictionary()
        );
    }

    [Fact]
    public void Test_extract_EC_key_from_JsonWebKey2020_secret()
    {
        var key = Key.FromSecret(
            new Secret
            (
                kid: "did:example:alice#key-p256-2",
                type: VerificationMethodType.JsonWebKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Jwk,
                    value: @"
                        {
                            ""kty"": ""EC"",
                            ""crv"": ""P-256"",
                            ""x"": ""2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY"",
                            ""y"": ""BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"",
                            ""d"": ""7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A""
                        }"
                )
            )
        );

        Assert.Equal("did:example:alice#key-p256-2", key.Id);
        Assert.Equal(Curve.P256, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "EC" },
                { "crv", "P-256" },
                { "x", "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY" },
                { "y", "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w" },
                { "d", "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A" },
            },
            key.Jwk.ToDictionary()
        );
    }

    [Fact]
    public void Test_extract_key_from_X25519KeyAgreementKey2019_verification_method()
    {
        var key = Key.FromVerificationMethod(
            new VerificationMethod
            (
                id: "did:example:dave#key-x25519-1",
                type: VerificationMethodType.X25519KeyAgreementKey2019,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Base58,
                    value: "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
                ),
                controller: "did:example:dave#key-x25519-1"
            )
        );
        Assert.Equal("did:example:dave#key-x25519-1", key.Id);
        Assert.Equal(Curve.X25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "X25519" },
                { "x", "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik" }
            },
            key.Jwk.ToDictionary()
        );
    }

    [Fact]
    public void Test_extract_key_from_X25519KeyAgreementKey2019_secret()
    {
        var key = Key.FromSecret(
            new Secret
            (
                kid: "did:example:eve#key-x25519-1",
                type: VerificationMethodType.X25519KeyAgreementKey2019,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Base58,
                    value: "2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqFyjLPWt7rv5kL3UPeG3e4B9Sy4H2Q2zAuWcP2RNtgJ4t"
                )
            )
        );
    
        Assert.Equal("did:example:eve#key-x25519-1", key.Id);
        Assert.Equal(Curve.X25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "X25519" },
                { "x", "piw5XSMkceDeklaHQZXPBLQySyAwF8eZ-vddihdURS0" },
                { "d", "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg" },
            },
            key.Jwk.ToDictionary()
        );
    }


    [Fact]
    public void Test_extract_key_from_Ed25519VerificationKey2018_verification_method()
    {
        var key = Key.FromVerificationMethod(
            new VerificationMethod
            (
                id: "did:example:dave#key-ed25519-1",
                type: VerificationMethodType.Ed25519VerificationKey2018,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Base58,
                    value: "ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7"
                ),
                controller: "did:example:dave#key-ed25519-1"
            )
        );
        Assert.Equal("did:example:dave#key-ed25519-1", key.Id);
        Assert.Equal(Curve.Ed25519, key.Curve);
        Assert.Equivalent(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "Ed25519" },
                { "x", "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA" }
            },
            new Dictionary<string, object>
            {
                { "kty", key.Jwk.Kty },
                { "crv", key.Jwk.Crv },
                { "x", key.Jwk.X }
            }
        );
    }

    [Fact]
    public void Test_extract_key_from_Ed25519VerificationKey2018_secret()
    {
        var key = Key.FromSecret(
            new Secret
            (
                kid: "did:example:eve#key-ed25519-1",
                type: VerificationMethodType.Ed25519VerificationKey2018,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Base58,
                    value: "2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqATnLmZDx7Seu6NqTuFKkxuHNT27GcoxVZQCkWJhNvaUQ"
                )
            )
        );

        Assert.Equal("did:example:eve#key-ed25519-1", key.Id);
        Assert.Equal(Curve.Ed25519, key.Curve);
        Assert.Equivalent(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "Ed25519" },
                { "x", "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE" },
                { "d", "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg" },
            },
            new Dictionary<string, object>
            {
                { "kty", key.Jwk.Kty },
                { "crv", key.Jwk.Crv },
                { "x", key.Jwk.X },
                { "d", key.Jwk.D }
            }
        );
    }

    [Fact]
    public void Test_extract_key_from_X25519KeyAgreementKey2020_verification_method()
    {
        var key = Key.FromVerificationMethod(
            new VerificationMethod
            (
                id: "did:example:dave#key-x25519-2",
                type: VerificationMethodType.X25519KeyAgreementKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Multibase,
                    value: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
                ),
                controller: "did:example:dave#key-x25519-2"
            )
        );
        Assert.Equal("did:example:dave#key-x25519-2", key.Id);
        Assert.Equal(Curve.X25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "X25519" },
                { "x", "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik" }
            },
            key.Jwk.ToDictionary()
        );
    }

    [Fact]
    public void Test_extract_key_from_X25519KeyAgreementKey2020_secret()
    {
        var key = Key.FromSecret(
            new Secret
            (
                kid: "did:example:eve#key-x25519-2",
                type: VerificationMethodType.X25519KeyAgreementKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Multibase,
                    value: "zshCmpUZKtFrAfudMf7NzD3oR6yhWe6i2434FDktk9CYZfkndn7suDrqnRWvrVDHk95Z7vBRJChFxTgBF9qzq7D3xPe"
                )
            )
        );
    
        Assert.Equal("did:example:eve#key-x25519-2", key.Id);
        Assert.Equal(Curve.X25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "X25519" },
                { "x", "piw5XSMkceDeklaHQZXPBLQySyAwF8eZ-vddihdURS0" },
                { "d", "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg" },
            },
            key.Jwk.ToDictionary()
        );
    }

    [Fact]
    public void Test_extract_key_from_Ed25519VerificationKey2020_verification_method()
    {
        var key = Key.FromVerificationMethod(
            new VerificationMethod
            (
                id: "did:example:dave#key-ed25519-2",
                type: VerificationMethodType.Ed25519VerificationKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Multibase,
                    value: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
                ),
                controller: "did:example:dave#key-ed25519-2"
            )
        );
    
        Assert.Equal("did:example:dave#key-ed25519-2", key.Id);
        Assert.Equal(Curve.Ed25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "Ed25519" },
                { "x", "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA" }
            },
            new Dictionary<string, object>
            {
                { "kty", key.Jwk.Kty },
                { "crv", key.Jwk.Crv },
                { "x", key.Jwk.X }
            }
        );
    }

    [Fact]
    public void Test_extract_key_from_Ed25519VerificationKey2020_secret()
    {
        var key = Key.FromSecret(
            new Secret
            (
                kid: "did:example:eve#key-ed25519-2",
                type: VerificationMethodType.Ed25519VerificationKey2020,
                verificationMaterial: new VerificationMaterial
                (
                    format: VerificationMaterialFormat.Multibase,
                    value: "zrv2DyJwnoQWzS74nPkHHdM7NYH27BRNFBG9To7Fca9YzWhfBVa9Mek52H9bJexjdNqxML1F3TGCpjLNkCwwgQDvd5J"
                )
            )
        );
    
        Assert.Equal("did:example:eve#key-ed25519-2", key.Id);
        Assert.Equal(Curve.Ed25519, key.Curve);
        Assert.Equal(
            new Dictionary<string, object>
            {
                { "kty", "OKP" },
                { "crv", "Ed25519" },
                { "x", "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE" },
                { "d", "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg" },
            },
            new Dictionary<string, object>
            {
                { "kty", key.Jwk.Kty },
                { "crv", key.Jwk.Crv },
                { "x", key.Jwk.X },
                { "d", key.Jwk.D }
            }
        );
    }
}