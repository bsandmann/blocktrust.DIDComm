namespace Blocktrust.DIDComm.Message.FromPriors;

public class FromPriorsBuilder
{
    public string Iss { get; set; }
    public string Sub { get; set; }
    internal string aud { get; set; }
    internal long? exp { get; set; }
    internal long? nbf { get; set; }
    internal long? iat { get; set; }
    internal string jti { get; set; }

    public FromPriorsBuilder(string iss, string sub)
    {
        this.Iss = iss;
        this.Sub = sub;
    }

    public FromPriorsBuilder Aud(string aud)
    {
        this.aud = aud;
        return this;
    }

    public FromPriorsBuilder Exp(long? exp)
    {
        this.exp = exp;
        return this;
    }

    public FromPriorsBuilder Nbf(long? nbf)
    {
        this.nbf = nbf;
        return this;
    }

    public FromPriorsBuilder Iat(long? iat)
    {
        this.iat = iat;
        return this;
    }

    public FromPriorsBuilder Jti(string jti)
    {
        this.jti = jti;
        return this;
    }

    public FromPrior Build() => new FromPrior(this);
}
