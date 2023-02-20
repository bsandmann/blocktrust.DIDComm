namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Keys;

public class JwsHeader
{
    //TODO very basic implementation of my own, needs to be extended

    public JwsHeader Builder(JwsAlgorithm alg, Key? key = null, string? typ = null)
    {
        if (key != null)
        {
            Header.Add("kid", key.Id);
        }

        if (typ != null)
        {
            Header.Add("typ", typ);
        }

        Header.Add("alg", alg.ToString());

        return this;
    }

    private Dictionary<string, object> Header { get; } = new Dictionary<string, object>();

    public Dictionary<string, object> Build()
    {
        return this.Header;
    }
    
    public string ToBase64()
    {
        //TODO do I use UTF( everytwhere? maybe ascii in some places? why then?
        var payloadBytes = Encoding.UTF8.GetBytes(this.ToString());
        return Base64Url.Encode(payloadBytes);
    }
    
    public override string ToString()
    {
        //TODO attention: it vital that this to string results in excatly the same string as the kotlin implementation
        //since this gets hashed and checked against the encryption
        //options?
        var r = JsonSerializer.Serialize(this.Header, SerializationOptions.UnsafeRelaxedEscaping);
        return r;
    }
}