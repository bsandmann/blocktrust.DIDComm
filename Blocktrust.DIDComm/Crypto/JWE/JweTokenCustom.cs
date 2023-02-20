namespace Blocktrust.DIDComm.Crypto.JWE;

public class JweTokenCustom
{
    public byte[] ProtectedHeaderBytes { get; }

    public IDictionary<string, object> UnprotectedHeader { get; }

    public List<JweRecipientCustom> Recipients { get; }

    public JweRecipientCustom Recipient { get; internal set; }

    public byte[] Aad { get; }

    public byte[] Iv { get; }

    public byte[] Ciphertext { get; }

    public byte[] PlaintextBytes { get; internal set; }

    public string Plaintext => this.PlaintextBytes != null ? System.Text.Encoding.UTF8.GetString(this.PlaintextBytes) : (string) null;

    public byte[] AuthTag { get; }
    
    
    public JweTokenCustom(
        byte[] protectedHeaderBytes,
        IDictionary<string, object> unprotectedHeader,
        List<JweRecipientCustom> recipients,
        byte[] aad,
        byte[] iv,
        byte[] ciphertext,
        byte[] authTag )
    {
        this.ProtectedHeaderBytes = protectedHeaderBytes;
        this.UnprotectedHeader = unprotectedHeader;
        this.Recipients = recipients;
        this.Aad = aad;
        this.Iv = iv;
        this.Ciphertext = ciphertext;
        this.AuthTag = authTag;
    }
}