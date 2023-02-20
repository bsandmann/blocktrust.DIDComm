namespace Blocktrust.DIDComm.Crypto;

using Exceptions;

public class Curve
{
    public const string CurveNameP256 = "P-256";
    public const string CurveNameSecp256k1 = "secp256k1";
    public const string CurveNameP256K = "P-256K";
    public const string CurveNameP384 = "P-384";
    public const string CurveNameP521 = "P-521";
    public const string CurveNameEd25519 = "Ed25519";
    public const string CurveNameEd448 = "Ed448";
    public const string CurveNameX25519 = "X25519";
    public const string CurveNameX448 = "X448";


    private static readonly long SerialVersionUid = 1L;
    
    public static readonly Curve P256 = new Curve(CurveNameP256, "secp256r1", "1.2.840.10045.3.1.7");
    
    public static readonly Curve Secp256K1 = new Curve(CurveNameSecp256k1, "secp256k1", "1.3.132.0.10");

    //[Deprecated]!!
    public static readonly Curve P256K = new Curve(CurveNameP256K, "secp256k1", "1.3.132.0.10");

    public static readonly Curve P384 = new Curve(CurveNameP384, "secp384r1", "1.3.132.0.34");

    public static readonly Curve P521 = new Curve(CurveNameP521, "secp521r1", "1.3.132.0.35");

    public static readonly Curve Ed25519 = new Curve(CurveNameEd25519, "Ed25519", null);

    public static readonly Curve Ed448 = new Curve(CurveNameEd448, "Ed448", null);

    public static readonly Curve X25519 = new Curve(CurveNameX25519, "X25519", null);

    public static readonly Curve X448 = new Curve(CurveNameX448, "X448", null);

    public readonly string Name;

    public readonly string? StdName;

    public readonly string? Oid;


    public Curve(string name, string stdName, string oid)
    {
        if (name == null)
        {
            throw new ArgumentNullException("The JOSE cryptographic curve name must not be null");
        }

        this.Name = name;
        this.StdName = stdName;
        this.Oid = oid;
    }


    public static Curve Parse(string s)
    {
        if (string.IsNullOrWhiteSpace(s))
        {
            throw new ArgumentException("The cryptographic curve string must not be null or empty");
        }

        if (s.Equals(P256.Name))
        {
            return P256;
        }
        else if (s.Equals(P256K.Name))
        {
            return P256K;
        }
        else if (s.Equals(P256K.Name))
        {
            return P256K;
        }
        else if (s.Equals(Secp256K1.Name))
        {
            return Secp256K1;
        }
        else if (s.Equals(P384.Name))
        {
            return P384;
        }
        else if (s.Equals(P521.Name))
        {
            return P521;
        }
        else if (s.Equals(Ed25519.Name))
        {
            return Ed25519;
        }
        else if (s.Equals(Ed448.Name))
        {
            return Ed448;
        }
        else if (s.Equals(X25519.Name))
        {
            return X25519;
        }
        else if (s.Equals(X448.Name))
        {
            return X448;
        }
        else
        {
            throw new UnsupportedJwkException("Unsupported curve");
        }
    }
}