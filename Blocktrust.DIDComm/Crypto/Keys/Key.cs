namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Exceptions;
using JWE;

public interface Key
{
    string Id { get; }
    Jwk Jwk { get; }
    Curve Curve { get; }

    public const int Curve25519PointSize = 32;

    static bool IsCurveBased(Jwk jwk)
    {
        var validCurves = new List<string>();
        validCurves.Add(Curve.CurveNameP256);
        validCurves.Add(Curve.CurveNameSecp256k1);
        validCurves.Add(Curve.CurveNameP256K);
        validCurves.Add(Curve.CurveNameP384);
        validCurves.Add(Curve.CurveNameP521);
        validCurves.Add(Curve.CurveNameEd25519);
        validCurves.Add(Curve.CurveNameEd448);
        validCurves.Add(Curve.CurveNameX25519);
        validCurves.Add(Curve.CurveNameX448);
        if (validCurves.Contains(jwk.Crv))
        {
            return true;
        }

        return false;
    }

    public static Key FromVerificationMethod(VerificationMethod method)
    {
        switch (method.Type)
        {
            case VerificationMethodType.JsonWebKey2020:
                if (method.VerificationMaterial.Format != VerificationMaterialFormat.Jwk)
                    throw new UnsupportedVerificationMethodMaterialFormatException(
                        method.VerificationMaterial.Format, method.Type
                    );
                return new JsonWebKey(method.Id, method.VerificationMaterial.Value);

            case VerificationMethodType.X25519KeyAgreementKey2019:
                // throw new UnsupportedVerificationMethodTypeException(method.type);
            case VerificationMethodType.Ed25519VerificationKey2018:
            {
                //TODO somwaht unclear waht all this is. Can be simplified ist if implementeted X25519
                if (method.VerificationMaterial.Format != VerificationMaterialFormat.Base58)
                    throw new UnsupportedVerificationMethodMaterialFormatException(
                        method.VerificationMaterial.Format, method.Type
                    );
                string curve;
                switch ((method.Type))
                {
                    case VerificationMethodType.X25519KeyAgreementKey2019:
                        curve = Curve.CurveNameX25519;
                        // throw new UnsupportedVerificationMethodTypeException(method.type);
                        break;
                    case VerificationMethodType.Ed25519VerificationKey2018:
                        curve = Curve.CurveNameEd25519;
                        break;
                    default:
                        throw new UnsupportedVerificationMethodTypeException(method.Type);
                }

                return new Base58PublicKey(method.Id, curve, method.VerificationMaterial.Value);
            }

            case VerificationMethodType.X25519KeyAgreementKey2020:
                // throw new UnsupportedVerificationMethodTypeException(method.type);
            case VerificationMethodType.Ed25519VerificationKey2020:
            {
                //TODO somwaht unclear waht all this is. Cann be simplified when implemtende x25519
                if (method.VerificationMaterial.Format != VerificationMaterialFormat.Multibase)
                    throw new UnsupportedVerificationMethodMaterialFormatException(
                        method.VerificationMaterial.Format, method.Type
                    );
                string curve;
                switch ((method.Type))
                {
                    case VerificationMethodType.X25519KeyAgreementKey2020:
                        curve = Curve.CurveNameX25519;
                        // throw new UnsupportedVerificationMethodTypeException(method.type);
                        break;
                    case VerificationMethodType.Ed25519VerificationKey2020:
                        curve = Curve.CurveNameEd25519;
                        break;
                    default:
                        throw new UnsupportedVerificationMethodTypeException(method.Type);
                }

                return new MultibasePublicKey(method.Id, curve, method.VerificationMaterial.Value);
            }

            default:
            {
                throw new UnsupportedVerificationMethodTypeException(method.Type);
            }
        }
    }

    public static Key FromSecret(Secret secret)
    {
        switch (secret.Type)
        {
            case VerificationMethodType.JsonWebKey2020:
                if (secret.VerificationMaterial.Format != VerificationMaterialFormat.Jwk)
                    throw new UnsupportedSecretMaterialFormatException(
                        secret.VerificationMaterial.Format, secret.Type
                    );
                return new JsonWebKey(secret.Kid, secret.VerificationMaterial.Value);

            case VerificationMethodType.X25519KeyAgreementKey2019:
            case VerificationMethodType.Ed25519VerificationKey2018:
                if (secret.VerificationMaterial.Format != VerificationMaterialFormat.Base58)
                    throw new UnsupportedSecretMaterialFormatException(
                        secret.VerificationMaterial.Format, secret.Type
                    );
                string curve_2018_2019;
                switch (secret.Type)
                {
                    //TODO can be simplified when implemented x25519
                    case VerificationMethodType.X25519KeyAgreementKey2019:
                        curve_2018_2019 = Curve.CurveNameX25519;
                        break;
                    case VerificationMethodType.Ed25519VerificationKey2018:
                        curve_2018_2019 = Curve.CurveNameEd25519;
                        break;
                    default:
                        throw new UnsupportedSecretTypeException(secret.Type);
                }

                return new Base58PrivateKey(secret.Kid, curve_2018_2019, secret.VerificationMaterial.Value);

            case VerificationMethodType.X25519KeyAgreementKey2020:
            case VerificationMethodType.Ed25519VerificationKey2020:
                if (secret.VerificationMaterial.Format != VerificationMaterialFormat.Multibase)
                    throw new UnsupportedSecretMaterialFormatException(
                        secret.VerificationMaterial.Format, secret.Type
                    );
                string curve_2020;
                switch (secret.Type)
                {
                    //TODO can be simplified when implemented x25519
                    case VerificationMethodType.X25519KeyAgreementKey2020:
                        curve_2020 = Curve.CurveNameX25519;
                        break;
                    case VerificationMethodType.Ed25519VerificationKey2020:
                        curve_2020 = Curve.CurveNameEd25519;
                        break;
                    default:
                        throw new UnsupportedSecretTypeException(secret.Type);
                }

                return new MultibasePrivateKey(secret.Kid, curve_2020, secret.VerificationMaterial.Value);

            default:
                throw new UnsupportedSecretTypeException(secret.Type);
        }
    }
}