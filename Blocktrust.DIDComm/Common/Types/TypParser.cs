namespace Blocktrust.DIDComm.Common.Types;

public class TypParser
{
    public static string Parse(string str)
    {
        switch (str)
        {
            case "application/didcomm-encrypted+json":
                return MessageTyp.Encrypted;
            case "application/didcomm-signed+json":
                return MessageTyp.Signed;
            case "application/didcomm-plain+json":
                return MessageTyp.Plaintext;
            default:
                throw new ArgumentException("Unsupported message typ");
        }
    }
}