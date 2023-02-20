namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Utils;

public class JweHeader
{
    public Dictionary<string, object> Header { get; } = new Dictionary<string, object>();
    public string RawJsonString { get; set; }

    public JweHeader Epk(Jwk joseObjectType)
    {
        //TODO unclear
        Header.Add("epk", joseObjectType);
        return this;
    }

    //TODO no clue, but for the start i copied the header from the jws 
    public JweHeader Builder(string alg, string enc)
    {
        if (alg != null)
        {
            Header.Add("alg", alg);
        }

        if (enc != null)
        {
            Header.Add("enc", enc);
        }

        return this;
    }

    public JweHeader Typ(string joseObjectType)
    {
        //TODO unclear
        Header.Add("typ", joseObjectType);
        return this;
    }


    public JweHeader AgreementPartyVInfo(string apv)
    {
        Header.Add("apv", apv);
        return this;
    }

    public JweHeader AgreementPartyUInfo(string apu)
    {
        Header.Add("apu", apu);
        return this;
    }

    public JweHeader SenderKeyId(string skid)
    {
        Header.Add("skid", skid);
        return this;
    }

    public string GetHeaderAlgorithm()
    {
        var alg = (string)Header["alg"];
        //TODO maybe verifiy against the available algos?
        // JweAlgorithmExtension.TryParse((string?)alg, out JweAlgorithmExtension algorithm);
        return alg;
    }

    public string GetHeaderEncryption()
    {
        var enc = (string)Header["enc"];
        //TODO maybe verifiy against the available encryptions?
        // JweEncryption.TryParse((string?)enc, out JweEncryption encryption);
        return enc;
    }

    public string GetAgreementPartyVInfo()
    {
        if (Header.ContainsKey("apv"))
        {
            var apv = (string)Header["apv"];
            return apv;
        }

        return null;
    }

    public string GetAgreementPartyUInfo()
    {
        if (Header.ContainsKey("apu"))
        {
            var apu = (string)Header["apu"];
            return apu;
        }

        return null;
    }

    public JweHeader Build()
    {
        return this;
    }

    public override string ToString()
    {
        //TODO attention: it vital that this to string results in excatly the same string as the kotlin implementation
        //since this gets hashed and checked against the encryption
        //options?
        var r = JsonSerializer.Serialize(this.Header, SerializationOptions.UnsafeRelaxedEscaping);
        return r;
    }

    public string ToBase64()
    {
        var payloadBytes = Encoding.UTF8.GetBytes(this.ToString());
        return Base64Url.Encode(payloadBytes);
    }

    public static JweHeader Parse(Dictionary<string, object> unprotectedHeader, string rawJsonString)
    {
        //TODO make a correct implementaiton of all of taht...
        //Maybe copy from JOSE?
        var alg = JsonUtils.GetTyped<string>(unprotectedHeader, "alg"); // (string)unprotectedHeader["alg"];
        var enc = JsonUtils.GetTyped<string>(unprotectedHeader, "enc"); //(string)unprotectedHeader["enc"];

        var builder = new JweHeader().Builder(alg, enc);
        if (unprotectedHeader.ContainsKey("epk"))
        {
            var dictionary = JsonUtils.GetObject(unprotectedHeader, "epk");
            var epk = Jwk.FromDictionary(dictionary);
            builder.Epk(epk);
        }

        if (unprotectedHeader.ContainsKey("apu"))
        {
            builder.AgreementPartyUInfo(JsonUtils.GetTyped<string>(unprotectedHeader, "apu"));
        }

        if (unprotectedHeader.ContainsKey("apv"))
        {
            builder.AgreementPartyVInfo(JsonUtils.GetTyped<string>(unprotectedHeader, "apv"));
        }

        if (unprotectedHeader.ContainsKey("skid"))
        {
            builder.SenderKeyId(JsonUtils.GetTyped<string>(unprotectedHeader, "skid"));
        }

        if (unprotectedHeader.ContainsKey("typ"))
        {
            builder.Typ(JsonUtils.GetTyped<string>(unprotectedHeader, "typ"));
        }

        var r = builder.Build();
        r.RawJsonString = rawJsonString;
        return r;
    }

    public static JweHeader Parse(string unprotectedHeader)
    {
        var bytes = Base64Url.Decode(unprotectedHeader);
        var json = Encoding.UTF8.GetString(bytes);
        var dictionary = JsonUtils.FromJsonToMap(json);
        return Parse(dictionary, json);
    }
}