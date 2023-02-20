//<summary>
//Algorithms for signature (non-repudiation)
//</summary>
namespace Blocktrust.DIDComm.Common.Algorithms;

public enum SignAlg
{
    /// <summary>
    /// Elliptic curve digital signature with edwards curves Ed25519 and SHA-512
    /// </summary>
    Ed25519,

    /// <summary>
    /// Elliptic curve digital signature with NIST p-256 curve and SHA-256
    /// </summary>
    Es256,

    /// <summary>
    /// Elliptic curve digital signature with Secp256k1 keys
    /// </summary>
    Es256K
}