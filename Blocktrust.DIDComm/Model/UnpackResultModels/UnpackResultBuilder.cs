namespace Blocktrust.DIDComm.Model.UnpackResultModels;

using Common.Algorithms;

public class UnpackResultBuilder
{
    public bool encrypted;
    public bool authenticated;
    public bool nonRepudiation;
    public bool anonymousSender;
    public bool reWrappedInForward;
    public List<string> encryptedTo;
    public string encryptedFrom;
    public string signFrom;
    public string fromPriorIssuerKid;
    public AuthCryptAlg encAlgAuth;
    public AnonCryptAlg encAlgAnon;
    public SignAlg? signAlg;
    public Dictionary<string, object> signedMessage;
    public string fromPriorJwt;

    public Metadata BuildUnpackResult()
    {
        return new Metadata(this);
    }
    
    public UnpackResultBuilder Encrypted(bool encrypted)
    {
        this.encrypted = encrypted;
        return this;
    }
    
    public UnpackResultBuilder Authenticated(bool authenticated)
    {
        this.authenticated = authenticated;
        return this;
    }
    
    public UnpackResultBuilder NonRepudiation(bool nonRepudiation)
    {
        this.nonRepudiation = nonRepudiation;
        return this;
    }
    
    public UnpackResultBuilder AnonymousSender(bool anonymousSender)
    {
        this.anonymousSender = anonymousSender;
        return this;
    }
    
    public UnpackResultBuilder ReWrappedInForward(bool reWrappedInForward)
    {
        this.reWrappedInForward = reWrappedInForward;
        return this;
    }
    
    public UnpackResultBuilder EncryptedTo(List<string> encryptedTo)
    {
        this.encryptedTo = encryptedTo;
        return this;
    }
    
    public UnpackResultBuilder EncryptedFrom(string encryptedFrom)
    {
        this.encryptedFrom = encryptedFrom;
        return this;
    }
    
    public UnpackResultBuilder SignFrom(string signFrom)
    {
        this.signFrom = signFrom;
        return this;
    }
    
    public UnpackResultBuilder FromPriorIssuerKid(string fromPriorIssuerKid)
    {
        this.fromPriorIssuerKid = fromPriorIssuerKid;
        return this;
    }
    
    public UnpackResultBuilder EncAlgAuth(AuthCryptAlg encAlgAuth)
    {
        this.encAlgAuth = encAlgAuth;
        return this;
    }
    
    public UnpackResultBuilder EncAlgAnon(AnonCryptAlg encAlgAnon)
    {
        this.encAlgAnon = encAlgAnon;
        return this;
    }
    
    public UnpackResultBuilder SignAlg(SignAlg signAlg)
    {
        this.signAlg = signAlg;
        return this;
    }
    
    public UnpackResultBuilder SignedMessage(Dictionary<string, object> signedMessage)
    {
        this.signedMessage = signedMessage;
        return this;
    }
    
    public UnpackResultBuilder FromPriorJwt(string fromPriorJwt)
    {
        this.fromPriorJwt = fromPriorJwt;
        return this;
    }
}