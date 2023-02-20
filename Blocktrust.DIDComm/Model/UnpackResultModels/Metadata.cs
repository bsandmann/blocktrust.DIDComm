namespace Blocktrust.DIDComm.Model.UnpackResultModels;

using Common.Algorithms;

public class Metadata
{
    public bool? Encrypted;
    public bool? Authenticated;
    public bool? NonRepudiation;
    public bool? AnonymousSender;
    public bool? ReWrappedInForward;
    public List<string>? EncryptedTo;
    public string? EncryptedFrom;
    public string? SignFrom;
    public string? FromPriorIssuerKid;
    public AuthCryptAlg? EncAlgAuth;
    public AnonCryptAlg? EncAlgAnon;
    public SignAlg? SignAlg;
    public Dictionary<string, object>? SignedMessage;
    public string? FromPriorJwt;

    public Metadata(UnpackResultBuilder unpackResultBuilder)
    {
        this.Encrypted = unpackResultBuilder.encrypted;
        this.Authenticated = unpackResultBuilder.authenticated;
        this.NonRepudiation = unpackResultBuilder.nonRepudiation;
        this.AnonymousSender = unpackResultBuilder.anonymousSender;
        this.ReWrappedInForward = unpackResultBuilder.reWrappedInForward;
        this.EncryptedTo = unpackResultBuilder.encryptedTo;
        this.EncryptedFrom = unpackResultBuilder.encryptedFrom;
        this.SignFrom = unpackResultBuilder.signFrom;
        this.FromPriorIssuerKid = unpackResultBuilder.fromPriorIssuerKid;
        this.EncAlgAuth = unpackResultBuilder.encAlgAuth;
        this.EncAlgAnon = unpackResultBuilder.encAlgAnon;
        this.SignAlg = unpackResultBuilder.signAlg;
        this.SignedMessage = unpackResultBuilder.signedMessage;
        this.FromPriorJwt = unpackResultBuilder.fromPriorJwt;
    }
    
    public Metadata(
        bool? encrypted = false, 
        bool? authenticated = false,
        bool? nonRepudiation = false,
        bool? anonymousSender =false,
        bool? reWrappedInForward = false,
        List<string>? encryptedTo = null,
        string? encryptedFrom = null,
        string? signFrom = null,
        string? fromPriorIssuerKid = null,
        AuthCryptAlg? encAlgAuth = null,
        AnonCryptAlg? encAlgAnon = null,
        SignAlg? signAlg = null,
        Dictionary<string, object>? signedMessage =null,
        string? fromPriorJwt = null)
    {
        this.Encrypted = encrypted;
        this.Authenticated = authenticated;
        this.NonRepudiation = nonRepudiation;
        this.AnonymousSender = anonymousSender;
        this.ReWrappedInForward = reWrappedInForward;
        this.EncryptedTo = encryptedTo;
        this.EncryptedFrom = encryptedFrom;
        this.SignFrom = signFrom;
        this.FromPriorIssuerKid = fromPriorIssuerKid;
        this.EncAlgAuth = encAlgAuth;
        this.EncAlgAnon = encAlgAnon;
        this.SignAlg = signAlg;
        this.SignedMessage = signedMessage;
        this.FromPriorJwt = fromPriorJwt;
    }

    
}