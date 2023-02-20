namespace Blocktrust.DIDComm.Utils;

public class Multibase
{
    private char prefix;
    private string alphabet;
    private string name;

    //TODO this is all translated from
//    https://github.com/changjiashuai/kotlin-multibase/blob/master/src/main/kotlin/io/ipfs/multiformats/multibase/MultiBase.kt

    public Multibase(string name, char prefix, string alphabet)
    {
        this.prefix = prefix;
        this.alphabet = alphabet;
        this.name = name;
    }

    public char Prefix
    {
        get { return prefix; }
    }

    public string Alphabet
    {
        get { return alphabet; }
    }

    public string Name
    {
        get { return name; }
    }

    public static readonly string BASE2_Name = "BASE2";
    public static readonly string BASE8_Name = "BASE8";
    public static readonly string BASE10_Name = "BASE10";
    public static readonly string BASE16_Name = "BASE16";
    public static readonly string BASE16_UPPER_Name = "BASE16_UPPER";
    public static readonly string BASE32_Name = "BASE32";
    public static readonly string BASE32_UPPER_Name = "BASE32_UPPER";
    public static readonly string BASE32_PAD_Name = "BASE32_PAD";
    public static readonly string BASE32_PAD_UPPER_Name = "BASE32_PAD_UPPER";
    public static readonly string BASE32_HEX_Name = "BASE32_HEX";
    public static readonly string BASE32_HEX_UPPER_Name = "BASE32_HEX_UPPER";
    public static readonly string BASE32_HEX_PAD_Name = "BASE32_HEX_PAD";
    public static readonly string BASE32_HEX_PAD_UPPER_Name = "BASE32_HEX_PAD_UPPER";
    public static readonly string BASE58_FLICKR_Name = "BASE58_FLICKR";
    public static readonly string BASE58_BTC_Name = "BASE58_BTC";
    public static readonly string BASE64_Name = "BASE64";
    public static readonly string BASE64_URL_Name = "BASE64_URL";
    public static readonly string BASE64_PAD_Name = "BASE64_PAD";
    public static readonly string BASE64_URL_PAD_Name = "BASE64_URL_PAD";

    public static readonly Multibase BASE2 = new Multibase(BASE2_Name, '0', "01");
    public static readonly Multibase BASE8 = new Multibase(BASE8_Name, '7', "01234567");
    public static readonly Multibase BASE10 = new Multibase(BASE10_Name, '9', "0123456789");
    public static readonly Multibase BASE16 = new Multibase(BASE16_Name, 'f', "0123456789abcdef");
    public static readonly Multibase BASE16_UPPER = new Multibase(BASE16_UPPER_Name, 'F', "0123456789ABCDEF");
    public static readonly Multibase BASE32 = new Multibase(BASE32_Name, 'b', "abcdefghijklmnopqrstuvwxyz234567");
    public static readonly Multibase BASE32_UPPER = new Multibase(BASE32_UPPER_Name, 'B', "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    public static readonly Multibase BASE32_PAD = new Multibase(BASE32_PAD_Name, 'c', "abcdefghijklmnopqrstuvwxyz234567=");
    public static readonly Multibase BASE32_PAD_UPPER = new Multibase(BASE32_PAD_UPPER_Name, 'C', "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=");
    public static readonly Multibase BASE32_HEX = new Multibase(BASE32_HEX_Name, 'v', "0123456789abcdefghijklmnopqrstuvw");
    public static readonly Multibase BASE32_HEX_UPPER = new Multibase(BASE32_HEX_UPPER_Name, 'V', "0123456789ABCDEFGHIJKLMNOPQRSTUVW");
    public static readonly Multibase BASE32_HEX_PAD = new Multibase(BASE32_HEX_PAD_Name, 't', "0123456789abcdefghijklmnopqrstuvw=");
    public static readonly Multibase BASE32_HEX_PAD_UPPER = new Multibase(BASE32_HEX_PAD_UPPER_Name, 'T', "0123456789ABCDEFGHIJKLMNOPQRSTUVW=");
    public static readonly Multibase BASE58_FLICKR = new Multibase(BASE58_FLICKR_Name, 'Z', "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ");
    public static readonly Multibase BASE58_BTC = new Multibase(BASE58_BTC_Name, 'z', "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    public static readonly Multibase BASE64 = new Multibase(BASE64_Name, 'm', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    public static readonly Multibase BASE64_URL = new Multibase(BASE64_URL_Name, 'u', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
    public static readonly Multibase BASE64_PAD = new Multibase(BASE64_PAD_Name, 'M', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");
    public static readonly Multibase BASE64_URL_PAD = new Multibase(BASE64_URL_PAD_Name, 'U', "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=");

    private static readonly SortedDictionary<char, Multibase> baseMap = new SortedDictionary<char, Multibase>();

    static Multibase()
    {
        baseMap[BASE2.prefix] = BASE2;
        baseMap[BASE8.prefix] = BASE8;
        baseMap[BASE10.prefix] = BASE10;
        baseMap[BASE16.prefix] = BASE16;
        baseMap[BASE16_UPPER.prefix] = BASE16_UPPER;
        baseMap[BASE32.prefix] = BASE32;
        baseMap[BASE32_UPPER.prefix] = BASE32_UPPER;
        baseMap[BASE32_PAD.prefix] = BASE32_PAD;
        baseMap[BASE32_PAD_UPPER.prefix] = BASE32_PAD_UPPER;
        baseMap[BASE32_HEX.prefix] = BASE32_HEX;
        baseMap[BASE32_HEX_UPPER.prefix] = BASE32_HEX_UPPER;
        baseMap[BASE32_HEX_PAD.prefix] = BASE32_HEX_PAD;
        baseMap[BASE32_HEX_PAD_UPPER.prefix] = BASE32_HEX_PAD_UPPER;
        baseMap[BASE58_FLICKR.prefix] = BASE58_FLICKR;
        baseMap[BASE58_BTC.prefix] = BASE58_BTC;
        baseMap[BASE64.prefix] = BASE64;
        baseMap[BASE64_URL.prefix] = BASE64_URL;
        baseMap[BASE64_PAD.prefix] = BASE64_PAD;
        baseMap[BASE64_URL_PAD.prefix] = BASE64_URL_PAD;
    }

    public static Multibase Lookup(char prefix)
    {
        if (baseMap.ContainsKey(prefix))
        {
            return baseMap[prefix];
        }
        else
        {
            throw new System.Exception("Unknown Multibase type: " + prefix);
        }
    }


    public static string Encode(Multibase multibase, string multibaseName, byte[] data)
    {
        switch (multibaseName)
        {
            case nameof(BASE58_BTC):
                return multibase.prefix + BaseN.Encode(multibase.alphabet, new System.Numerics.BigInteger(58), data);
            default:
                throw new System.Exception("UnImplement multi type");
        }
    }

    public static byte[] Decode(string data, string multibaseNameSelector = null)
    {
        Multibase multibase;
        string rest = data;
        if (multibaseNameSelector != null)
        {
            multibase = baseMap.Single(p => p.Value.name == multibaseNameSelector).Value;
        }
        else
        {
            char prefix = data[0];
            multibase = Multibase.Lookup(prefix);
            rest = data.Substring(1);
        }

        //TODO this is incorrect. I need the name here
        switch (multibase.name)
        {
            case nameof(BASE58_BTC):
                return BaseN.Decode(multibase.alphabet, new System.Numerics.BigInteger(58), rest);
            default:
                throw new System.Exception("UnImplement multi type");
        }
    }
}