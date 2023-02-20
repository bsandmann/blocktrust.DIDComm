namespace Blocktrust.DIDComm.Crypto.JWE;

public interface IJWEEncrypterMulti
{
    public JweCryptoParts Encrypt(JweHeader header, JwePayload Payload);
}