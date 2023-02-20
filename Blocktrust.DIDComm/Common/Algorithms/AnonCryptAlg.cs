//<summary>
//Algorithms for anonymous encryption.
//</summary>

namespace Blocktrust.DIDComm.Common.Algorithms;

public class AnonCryptAlg : CryptAlg
{
    /// <summary>
    /// A256CBC_HS512_ECDH_ES_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    /// </summary>
    public const string A256CBC_HS512_ECDH_ES_A256KW = "A256CBC_HS512_ECDH_ES_A256KW";

    /// <summary>
    /// XC20P_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    /// </summary>
    public const string XC20P_ECDH_ES_A256KW = "XC20P_ECDH_ES_A256KW";

    /// <summary>
    /// A256GCM_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    /// </summary>
    public const string A256GCM_ECDH_ES_A256KW = "A256GCM_ECDH_ES_A256KW";

    public string CryptAlg { get; }

    public AnonCryptAlg(string cryptAlg)
    {
        if (!(cryptAlg.Equals(A256GCM_ECDH_ES_A256KW) || cryptAlg.Equals(A256CBC_HS512_ECDH_ES_A256KW) || cryptAlg.Equals(XC20P_ECDH_ES_A256KW)))
        {
            throw new ArgumentException("Invalid cryptAlg");
        }

        this.CryptAlg = cryptAlg;
    }
}