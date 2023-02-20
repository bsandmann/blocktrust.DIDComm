namespace Blocktrust.DIDComm.Utils;

public static class Arrays
{
    //TODO IL code copied from JOSE lib
    public static byte[] FirstHalf(byte[] arr)
    {
        if (arr.Length % 2 != 0)
        {
            throw new Exception("Arrays.FirstHalf() expects even number of element in array.");
        }
        int count = arr.Length / 2;
        byte[] dst = new byte[count];
        Buffer.BlockCopy((Array) arr, 0, (Array) dst, 0, count);
        return dst;
    }

    //TODO IL code copied from JOSE lib
    public static byte[] SecondHalf(byte[] arr)
    {
        if (arr.Length % 2 != 0)
        {
            throw new Exception("Arrays.SecondHalf() expects even number of element in array.");
        }
        int length = arr.Length / 2;
        byte[] dst = new byte[length];
        Buffer.BlockCopy((Array) arr, length, (Array) dst, 0, length);
        return dst;
    }
}