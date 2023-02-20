//<summary>
//Algorithms for authentication encryption.
//</summary>
namespace Blocktrust.DIDComm.Common.Algorithms;

public class AuthCryptAlg : CryptAlg
{
    /// <summary>
    /// A256CBC_HS512_ECDH_1PU_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-1PU key agreement with A256KW key wrapping
    /// </summary>
    public const string A256CBC_HS512_ECDH_1PU_A256KW = "A256CBC_HS512_ECDH_1PU_A256KW";

    public string CryptAlg { get; }

    public AuthCryptAlg(string cryptAlg)
    {
        if (!(cryptAlg.Equals(A256CBC_HS512_ECDH_1PU_A256KW)))
        {
            throw new ArgumentException("Invalid cryptAlg");
        }
        CryptAlg = cryptAlg;
    }
}