namespace Blocktrust.DIDComm.Crypto.JWE;

//TODO would be better served as a enum, but not possible
public static class EncryptionMethod
{
    public static readonly string A256CBC_HS512 = "A256CBC-HS512";
    public static readonly string A256GCM = "A256GCM";
    public static readonly string XC20P = "XC20P";

    public static int GetEncryptionLength(string enc)
    {
        return enc switch
        {
            "A256CBC-HS512" => 512,
            "A256GCM" => 256,
            "XC20P" => 256,
            _ => throw new Exception()
        };
    }
}