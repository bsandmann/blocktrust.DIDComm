namespace Blocktrust.DIDComm.Crypto.JWE;

public enum JweTokenState
{
    Unencrypted,


    /**
         * The JWE object is encrypted.
         */
    Encrypted,


    /**
         * The JWE object is decrypted.
         */
    Decrypted
}