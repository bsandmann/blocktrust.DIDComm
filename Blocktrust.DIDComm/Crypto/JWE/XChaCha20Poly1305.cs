namespace Blocktrust.DIDComm.Crypto.JWE;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

public class XChaCha20Poly1305
{
    // Reference implementation https://www.scottbrady91.com/c-sharp/xchacha20-poly1305-dotnet
    // Also see source code here https://github.com/scottbrady91/Blog-Example-Classes/blob/master/Rolling%20Your%20Own%20Crypto%20in%20.NET%20with%20XChaCha20-Poly1305/ScottBrady.Samples.XChaCha20Poly1305/BouncyDancing.cs#L11
   
    public static (byte[] ciphertext, byte[] authTag) Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        var encryptAlternative = Xc20PAlgorithm(true, key, nonce, plaintext, aad);
        var ciphertext = encryptAlternative.Take(encryptAlternative.Length - 16).ToArray();
        var authTag = encryptAlternative.Skip(ciphertext.Count()).ToArray();

        if (plaintext.Length != ciphertext.Length) throw new Exception("Unexpected encryption result");
        if (authTag.Length != 16) throw new Exception("Unexpected encryption result");
        
        return (ciphertext, authTag);
    }

    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
    {
        return Xc20PAlgorithm(false, key, nonce, ciphertext, aad);
    }

    private static byte[] Xc20PAlgorithm(bool isEncryption, byte[] key, byte[] nonce, byte[] message, byte[] aad)
    {
        if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes", nameof(key));
        if (nonce.Length != 24) throw new ArgumentException("Nonce must be 24 bytes", nameof(nonce));

        // subkey (hchacha20(key, nonce[0:15]))
        var subkey = HChaCha20.CreateSubkey(key, nonce); // TODO: parse nonce bytes to pass through here instead

        // nonce (chacha20_nonce = "\x00\x00\x00\x00" + nonce[16:23])
        var chaChaNonce = new byte[12];
        Array.Copy(new byte[] { 0, 0, 0, 0 }, chaChaNonce, 4);
        Array.Copy(nonce, 16, chaChaNonce, 4, 8);

        // chacha20_encrypt(subkey, chacha20_nonce, plaintext, blk_ctr)
        var outputLength = message.Length;
        if (isEncryption) outputLength += 16;
        else outputLength -= 16;

        var output = new byte[outputLength];
        var keyMaterial = new KeyParameter(subkey);
        var parameters = new ParametersWithIV(keyMaterial, chaChaNonce);

        var chaCha20Poly1305 = new ChaCha20Poly1305();
        chaCha20Poly1305.Init(isEncryption, parameters);

        chaCha20Poly1305.ProcessAadBytes(aad, 0, aad.Length);

        var len = chaCha20Poly1305.ProcessBytes(message, 0, message.Length, output, 0);
        chaCha20Poly1305.DoFinal(output, len);

        return output;
    }
}