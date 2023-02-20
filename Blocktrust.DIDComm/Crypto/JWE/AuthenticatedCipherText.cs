namespace Blocktrust.DIDComm.Crypto.JWE;

public class AuthenticatedCipherText
{
    public byte[] CipherText { get; set; }
    public byte[] AuthenticationTag { get; set; }
}