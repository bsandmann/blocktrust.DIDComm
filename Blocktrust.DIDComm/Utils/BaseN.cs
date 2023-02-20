namespace Blocktrust.DIDComm.Utils
{
    using System.Numerics;
    using SimpleBase;

    public static class BaseN
    {
        public static byte[] Decode(string alphabet, BigInteger bigInt, string input)
        {
            return Base58.Bitcoin.Decode(input);
        }

        public static string Encode(string alphabet, BigInteger bigInt, byte[] input)
        {
            return Base58.Bitcoin.Encode(input);
        }
      
    }
}