namespace Blocktrust.DIDComm.Crypto.JWE;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Utils;

public class AESCBCEncryptor
{
    private const string Algorithm = "AES";
    private const string CipherMode = "CBC";
    private const string _algorithm = $"{Algorithm}/{CipherMode}/PKCS7";

    //AAD - Aditional Authenticated Data / TAG (authentication tag)

    public AuthenticatedCipherText Encrypt(byte[] plainText, byte[] cek, byte[] aad, byte[] iv)
    {
        byte[] macKey = Arrays.FirstHalf(cek);
        byte[] encKey = Arrays.SecondHalf(cek); //AES key

        var keyParameters = CreateKeyParameters(encKey, iv);
        var cipher = CipherUtilities.GetCipher(_algorithm);
        cipher.Init(true, keyParameters);

        var cipherText = cipher.DoFinal(plainText);
        byte[] al = ComputeLength(aad);

        int hmacInputLength = aad.Length + iv.Length + cipherText.Length + al.Length;
        byte[] hmacInput = new byte[hmacInputLength];
        var hmac = GenerateHMAC(aad, hmacInput, iv, cipherText, al, macKey);
        //TODO should be above. compare with kotlin
        
        // The authtag is the first 32 bytes of the HMAC
        byte[] authTag = hmac.Take(32).ToArray();

        return new AuthenticatedCipherText()
        {
            CipherText = cipherText,
            AuthenticationTag = authTag
        };
    }

    public static byte[] DecryptAuthenticated(byte[] cek, byte[] iv, byte[] cipherText, byte[] aad, byte[] authTag)
    {
            byte[] al = AESCBCEncryptor.ComputeLength(aad);
            int hmacInputLength = aad.Length + iv.Length + cipherText.Length + al.Length;    
            byte[] hmacInput = new byte[hmacInputLength];
            var macKey = cek[0..32];
            var aesKey = cek[32..64];

            var hmac = GenerateHMAC(aad, hmacInput, iv, cipherText, al, macKey);
            byte[] ExpectedAuthTag = hmac.Take(32).ToArray();
            if (!ExpectedAuthTag.SequenceEqual(authTag))
            {
                throw new Exception("Mac check failed");
            }

            byte[] decryptResult = Decrypt(aesKey, iv, cipherText);
            return decryptResult;
    }


    private static byte[] GenerateHMAC(byte[] aad, byte[] hmacInput, byte[] iv, byte[] cipherText, byte[] al, byte[] macKey)
    {
        int index = 0;
        Buffer.BlockCopy(aad, 0, hmacInput, index, aad.Length);
        index += aad.Length;
        Buffer.BlockCopy(iv, 0, hmacInput, index, iv.Length);
        index += iv.Length;
        Buffer.BlockCopy(cipherText, 0, hmacInput, index, cipherText.Length);
        index += cipherText.Length;
        Buffer.BlockCopy(al, 0, hmacInput, index, al.Length);

        //TODO this is currently fixed on using HMAC 512
        HMac hmac = new HMac(new Sha512Digest());
        hmac.Init(new KeyParameter(macKey));
        hmac.BlockUpdate(hmacInput, 0, hmacInput.Length);
        byte[] result = new byte[hmac.GetMacSize()];
        hmac.DoFinal(result, 0);
        return result;
    }

    public static byte[] Decrypt(byte[] cek, byte[] iv, byte[] cipherText)
    {
        // Ensure.That(key.Length).Is(32);
        var keyParameters = CreateKeyParameters(cek, iv);
        var cipher = CipherUtilities.GetCipher(_algorithm);
        cipher.Init(false, keyParameters);

        var decryptedData = cipher.DoFinal(cipherText);
        return decryptedData;
    }

    private static ICipherParameters CreateKeyParameters(byte[] key, byte[] iv)
    {
        var keyParameter = new KeyParameter(key);
        return new ParametersWithIV(keyParameter, iv);
    }


    //translated with chatgpt - maybe there is a livery for this
    public static byte[] ComputeLength(byte[] aad)
    {
        int bitLength = SafeBitLength(aad);
        byte[] result = new byte[8];
        BitConverter.GetBytes(bitLength).CopyTo(result, 0);
        Array.Reverse(result);
        return result;
    }

    //translated with chatgpt - maybe there is a livery for this
    private static int SafeBitLength(byte[] aad)
    {
        int bitLength = aad.Length * 8;
        if (aad.Length > 0 && (aad[aad.Length - 1] & 0xF0) == 0)
        {
            int trailingZeros = 0;
            for (int i = aad.Length - 1; i >= 0 && (aad[i] & 0xF0) == 0; i--)
            {
                trailingZeros += 4;
            }

            for (int i = aad.Length - 1; i >= 0 && (aad[i] & 0xF0) == 0; i--)
            {
                trailingZeros++;
            }

            bitLength -= trailingZeros;
        }

        return bitLength;
    }

}