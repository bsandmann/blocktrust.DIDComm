namespace Blocktrust.DIDComm.Utils;

using System;
using System.Linq;
using System.Security.Cryptography;
using Blocktrust.Common.Converter;

public class DidUtils
{
    public static bool IsDidFragment(string str) => str.Contains("#");

    public static string[] DivideDidFragment(string str) => str.Split('#');

    public static string GetDid(string str) => DivideDidFragment(str)[0];

    public static bool IsDid(string str)
    {
        var parts = str.Split(':');
        return parts.Length >= 3 && parts[0] == "did";
    }

    public static bool IsDidUrl(string str)
    {
        var parts = DivideDidFragment(str);
        return parts.Length == 2 && IsDid(parts[0]) && parts[1] != "";
    }

    public static bool IsDidOrDidUrl(string str) => IsDid(str) || IsDidUrl(str);

    public static string CalculateApv(List<string> kids)
    {
        var byteArray = System.Text.Encoding.ASCII.GetBytes(String.Join(".", kids.OrderBy(x => x)));
        //TODO replace with bouncy castle
        return Base64Url.Encode(SHA256.Create().ComputeHash(byteArray));
    }

    public static string IdGeneratorDefault() => Guid.NewGuid().ToString();

    public static string DidCommIdGeneratorDefault(string did = null)
    {
        var res = IdGeneratorDefault();
        if (did != null)
        {
            res = $"{did}:{res}";
        }

        return res;
    }
}