namespace Blocktrust.DIDComm.Common.Types;

//TODO currently not used
public class DIDCommMessageProtocolTypesParser
{
    public static DIDCommMessageProtocolTypes Parse(string str)
    {
        if (str.Equals(DIDCommMessageProtocolTypes.Forward.ToString(), StringComparison.InvariantCultureIgnoreCase))
        {
            return DIDCommMessageProtocolTypes.Forward;
        }
        else
        {
            throw new ArgumentException("Unsupported protocol typ");
        }
    }
}