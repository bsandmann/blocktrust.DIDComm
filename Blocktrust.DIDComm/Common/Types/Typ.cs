namespace Blocktrust.DIDComm.Common.Types;

public static class MessageTyp
{
    //TODO for solutions look here: https://josipmisko.com/posts/string-enums-in-c-sharp-everything-you-need-to-know
    public static readonly string Encrypted = "application/didcomm-encrypted+json";
    public static readonly string Signed = "application/didcomm-signed+json";
    public static readonly string Plaintext = "application/didcomm-plain+json";
}