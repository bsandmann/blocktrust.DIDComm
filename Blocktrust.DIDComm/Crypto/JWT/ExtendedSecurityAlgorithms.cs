namespace Blocktrust.DIDComm.Crypto.JWT;

public static class ExtendedSecurityAlgorithms
{
    public class Curves
    {
        // https://tools.ietf.org/html/rfc8037#section-5
        public const string Ed25519 = "Ed25519";
        public const string Ed448 = "Ed448";
        public const string X25519 = "X25519";
    }
}