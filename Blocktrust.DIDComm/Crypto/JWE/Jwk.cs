namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Utils;

public class Jwk
{
    private byte[] _octKey;
    private System.Security.Cryptography.CngKey _eccCngKey;
    private ECDsa _ecdsaKey;

    [JsonPropertyName("kty")] public string Kty { get; set; }

    [JsonPropertyName("use")] public string Use { get; set; }

    [JsonPropertyName("alg")] public string Alg { get; set; }

    [JsonPropertyName("keyId")] public string KeyId { get; set; }

    [JsonPropertyName("keyOps")] public List<string> KeyOps { get; set; }

    [JsonPropertyName("k")] public string K { get; set; }

    [JsonPropertyName("n")] public string N { get; set; }

    [JsonPropertyName("e")] public string E { get; set; }

    [JsonPropertyName("d")] public string D { get; set; }

    [JsonPropertyName("p")] public string P { get; set; }

    [JsonPropertyName("dp")] public string DP { get; set; }

    [JsonPropertyName("q")] public string Q { get; set; }

    [JsonPropertyName("dq")] public string DQ { get; set; }

    [JsonPropertyName("qi")] public string QI { get; set; }

    [JsonPropertyName("crv")] public string Crv { get; set; }

    [JsonPropertyName("x")] public string X { get; set; }

    [JsonPropertyName("y")] public string Y { get; set; }

    [JsonPropertyName("x5u")] public string X5U { get; set; }

    [JsonPropertyName("x5t")] public string X5T { get; set; }

    [JsonPropertyName("x5tsha256")] public string X5TSha256 { get; set; }

    [JsonPropertyName("x5c")] public List<string> X5C { get; set; }

    [JsonPropertyName("otherParams")] public IDictionary<string, object> OtherParams { get; set; }

    public Jwk()
    {
    }

    public Jwk(string crv, string x, string y, string d = null)
    {
        this.Kty = "EC";
        this.Crv = crv;
        this.X = x;
        this.Y = y;
        this.D = d;
    }

    public static Jwk FromDictionary(Dictionary<string, object> data)
    {
        HashSet<string> keys = new HashSet<string>()
        {
            "kty",
            "use",
            "alg",
            "kid",
            "key_ops",
            "k",
            "e",
            "n",
            "d",
            "p",
            "q",
            "dp",
            "dq",
            "qi",
            "crv",
            "x",
            "y",
            "x5u",
            "x5c",
            "x5t",
            "x5t#S256"
        };
        return new Jwk()
        {
            Kty = JsonUtils.GetTyped<string>(data, "kty"),
            Use = JsonUtils.GetTyped<string>(data, "use"),
            Alg = JsonUtils.GetTyped<string>(data, "alg"),
            KeyId = JsonUtils.GetTyped<string>(data, "kid"),
            // KeyOps = Dictionaries.GetList<string>(data, "key_ops"),
            K = JsonUtils.GetTyped<string>(data, "k"),
            E = JsonUtils.GetTyped<string>(data, "e"),
            N = JsonUtils.GetTyped<string>(data, "n"),
            D = JsonUtils.GetTyped<string>(data, "d"),
            P = JsonUtils.GetTyped<string>(data, "p"),
            Q = JsonUtils.GetTyped<string>(data, "q"),
            DP = JsonUtils.GetTyped<string>(data, "dp"),
            DQ = JsonUtils.GetTyped<string>(data, "dq"),
            QI = JsonUtils.GetTyped<string>(data, "qi"),
            Crv = JsonUtils.GetTyped<string>(data, "crv"),
            X = JsonUtils.GetTyped<string>(data, "x"),
            Y = JsonUtils.GetTyped<string>(data, "y"),
            X5U = JsonUtils.GetTyped<string>(data, "x5u"),
            X5T = JsonUtils.GetTyped<string>(data, "x5t"),
            X5TSha256 = JsonUtils.GetTyped<string>(data, "x5t#S256"),
        };
    }

    public IDictionary<string, object> ToDictionary()
    {
        Dictionary<string, object> src = new Dictionary<string, object>();
        src["kty"] = (object)this.Kty;
        if (this.KeyId != null)
            src["kid"] = (object)this.KeyId;
        if (this.Use != null)
            src["use"] = (object)this.Use;
        if (this.KeyOps != null)
            src["key_ops"] = (object)this.KeyOps;
        if (this.Alg != null)
            src["alg"] = (object)this.Alg;
        if (this.Kty == "OKP")
        {
            src["crv"] = (object)this.Crv;
            if (this.X != null)
            {
                src["x"] = (object)this.X;
            }

            if (this.D != null)
            {
                src["d"] = (object)this.D;
            }
        }
        if (this.Kty == "EC")
        {
            src["crv"] = (object)this.Crv;
            src["x"] = (object)this.X;
            src["y"] = (object)this.Y;
            if (this.D != null)
            {
                src["d"] = (object)this.D;
            }
        }

        if (this.X5U != null)
            src["x5u"] = (object)this.X5U;
        if (this.X5T != null)
            src["x5t"] = (object)this.X5T;
        if (this.X5TSha256 != null)
            src["x5t#S256"] = (object)this.X5TSha256;
        if (this.X5C != null)
            src["x5c"] = (object)this.X5C;
        if (this.OtherParams != null)
        {
            foreach (var otherParam in this.OtherParams)
            {
                src.Append(otherParam);
            }
        }

        return (IDictionary<string, object>)src;
    }
}