namespace Blocktrust.DIDComm.Crypto.JWE;

public interface IJWEDecrypterMulti
{
    byte[] DecryptPayload(JweHeader unprotectedHeader, List<JweRecipientCustom> recipients, string iv, string cipherText, string authTag);
}