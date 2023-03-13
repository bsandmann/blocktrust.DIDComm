namespace Blocktrust.DIDComm.Tests;

using System.Text.Json;
using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;
using Crypto;
using Crypto.JWE;
using TestData.DIDDoc;
using TestData.Mock;

public static class TestUtils
{
    public enum Person
    {
        ALICE = 1,
        BOB = 2,
        CHARLIE = 3,
        MEDIATOR1 = 4,
        MEDIATOR2 = 5
    }

    public enum KeyAgreementCurveType
    {
        ALL = 0,
        X25519 = 1,
        P256 = 2,
        P384 = 3,
        P521 = 4
    }

    public static readonly Dictionary<Person, (DidDoc, ISecretResolver)> DIDDocsSpec = new Dictionary<Person, (DidDoc, ISecretResolver)>
    {
        //TODO unclear if this results in the correct name
        { Person.ALICE, (DIDDocAlice.DID_DOC_ALICE_WITH_NO_SECRETS, new AliceSecretResolverMock()) },
        { Person.BOB, (DIDDocBob.DID_DOC_BOB_WITH_NO_SECRETS, new BobSecretResolverMock()) },
        { Person.CHARLIE, (DIDDocCharlie.DID_DOC_CHARLIE, new CharlieSecretResolverMock()) },
        { Person.MEDIATOR1, (DIDDocMediator1.DID_DOC_MEDIATOR1, new Mediator1SecretResolverMock()) },
        { Person.MEDIATOR2, (DIDDocMediator2.DID_DOC_MEDIATOR2, new Mediator2SecretResolverMock()) }
    };

    public static DidDoc GetDidDoc(Person person)
    {
        return DIDDocsSpec.FirstOrDefault(p => p.Key == person).Value.Item1;
    }

    public static SecretResolverInMemoryMock GetSecretsResolver(Person person)
    {
        return (SecretResolverInMemoryMock)DIDDocsSpec.FirstOrDefault(p => p.Key == person).Value.Item2;
    }

    public static List<VerificationMethod> GetAuthMethodsInSecrets(Person person)
    {
        var didDoc = GetDidDoc(person);
        var secretsResolver = GetSecretsResolver(person);
        return didDoc.VerificationMethods.Where(vm => secretsResolver.GetSecretKids().Contains(vm.Id) && didDoc.Authentications.Contains(vm.Id)).ToList();
    }

    public static List<VerificationMethod> GetAuthMethodsNotInSecrets(Person person)
    {
        var didDoc = GetDidDoc(person);
        var secretsResolver = GetSecretsResolver(person);
        return didDoc.VerificationMethods.Where(vm =>
            !secretsResolver.GetSecretKids().Contains(vm.Id) &&
            didDoc.Authentications.Contains(vm.Id)
        ).ToList();
    }

    public static List<VerificationMethod> GetKeyAgreementMethodsInSecrets(
        Person person,
        KeyAgreementCurveType type = KeyAgreementCurveType.ALL
    )
    {
        var didDoc = GetDidDoc(person);
        var secretsResolver = GetSecretsResolver(person);
        return didDoc.VerificationMethods.Where(vm =>
            secretsResolver.GetSecretKids().Contains(vm.Id) &&
            didDoc.KeyAgreements.Contains(vm.Id) &&
            (type == KeyAgreementCurveType.ALL || type == MapCureToType(vm))
        ).ToList();
    }

    public static List<VerificationMethod> GetKeyAgreementMethodsNotInSecrets(
        Person person,
        KeyAgreementCurveType type = KeyAgreementCurveType.ALL
    )
    {
        var didDoc = GetDidDoc(person);
        var secretsResolver = GetSecretsResolver(person);
        return didDoc.VerificationMethods.Where(vm =>
            !secretsResolver.GetSecretKids().Contains(vm.Id) &&
            didDoc.KeyAgreements.Contains(vm.Id) &&
            (type == KeyAgreementCurveType.ALL || type == MapCureToType(vm))
        ).ToList();
    }

    public static List<VerificationMethod> GetKeyAgreementMethods(
        Person person,
        KeyAgreementCurveType type = KeyAgreementCurveType.ALL
    )
    {
        var didDoc = GetDidDoc(person);
        var dd = didDoc.VerificationMethods.Where(vm =>
            didDoc.KeyAgreements.Contains(vm.Id)).ToList();
        return didDoc.VerificationMethods.Where(vm =>
            didDoc.KeyAgreements.Contains(vm.Id) &&
            (type == KeyAgreementCurveType.ALL || type == MapCureToType(vm))
        ).ToList();
    }

    public static List<Blocktrust.Common.Models.Secrets.Secret> GetKeyAgreementSecrets(
        Person person,
        KeyAgreementCurveType type = KeyAgreementCurveType.ALL
    )
    {
        var didDoc = GetDidDoc(person);
        var secretsResolver = GetSecretsResolver(person);

        return secretsResolver.GetSecrets().Where(s =>
            didDoc.KeyAgreements.Contains(s.Kid) &&
            (type == KeyAgreementCurveType.ALL || type == MapCureToType(s))
        ).ToList();
    }

    private static KeyAgreementCurveType MapCureToType(Blocktrust.Common.Models.Secrets.Secret vm)
    {
        if (
            vm.Type == VerificationMethodType.JsonWebKey2020 &&
            vm.VerificationMaterial.Format == VerificationMaterialFormat.Jwk
        )
        {
            var jwk = ParseJwk(vm.VerificationMaterial);
            switch (jwk.Crv)
            {
                case Curve.CurveNameX25519: // "X25519":
                    return KeyAgreementCurveType.X25519;
                case Curve.CurveNameP256: // "P-256":
                    return KeyAgreementCurveType.P256;
                case Curve.CurveNameP384: // "P-384":
                    return KeyAgreementCurveType.P384;
                case Curve.CurveNameP521: // "P-521":
                    return KeyAgreementCurveType.P521;
                default:
                    //TODO Attention ! Code duplication
                    throw new NotSupportedException("??");
            }
        }

        throw new System.ArgumentException("Unknown verification methods curve type: " + vm);
    }

    private static KeyAgreementCurveType MapCureToType(VerificationMethod vm)
    {
        if (
            vm.Type == VerificationMethodType.JsonWebKey2020 &&
            vm.VerificationMaterial.Format == VerificationMaterialFormat.Jwk
        )
        {
            var jwk = ParseJwk(vm.VerificationMaterial);
            switch (jwk.Crv)
            {
                case Curve.CurveNameX25519: // "X25519":
                    return KeyAgreementCurveType.X25519;
                case Curve.CurveNameP256: // "P-256":
                    return KeyAgreementCurveType.P256;
                case Curve.CurveNameP384: // "P-384":
                    return KeyAgreementCurveType.P384;
                case Curve.CurveNameP521: // "P-521":
                    return KeyAgreementCurveType.P521;
                default:
                    //TODO Attention ! Code duplication
                    throw new NotSupportedException("??");
            }
        }

        throw new ArgumentException($"Unknown verification methods curve type: {vm}");
    }

    private static Jwk ParseJwk(VerificationMaterial verificationMaterial)
    {
        if (verificationMaterial.Format == VerificationMaterialFormat.Jwk)
        {
            var deserialized = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(verificationMaterial.Value);
            var dict = new Dictionary<string, object>();
            foreach (var kvpair in deserialized)
            {
                var jsonElement = (JsonElement)kvpair.Value;
                if (jsonElement.ValueKind == JsonValueKind.String)
                {
                    dict.Add(kvpair.Key, jsonElement.GetString());
                }
                else
                {
                    throw new Exception("Chance to improve the code");
                }
            }

            return Jwk.FromDictionary(dict);
        }
        else
        {
            throw new Exception("unclear");
        }

        return null;
    }

    public static List<List<object>> CartesianProduct(List<object> a, List<object> b, params List<object>[] lists)
    {
        return (new List<List<object>> { a, b }.Concat(lists))
            .Aggregate(new List<List<object>> { new List<object>() }, (acc, set) =>
                acc.SelectMany(list => set.Select(element => list.Concat(new List<object> { element }).ToList())).ToList()
            ).ToList();
    }
    
  
}