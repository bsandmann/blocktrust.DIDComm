namespace Blocktrust.DIDComm.Utils;

using Crypto.JWE;
using Crypto.JWM;

public static class JwkUtils
{
    //TODO
    public static T AsKey<T>(this Jwk jwk)
    {
        if (!(jwk is T))
        {
            throw new InvalidCastException($"Can not cast JWK to {typeof(T).Name}");
        }
    
        return (T)(object)jwk;
    }
    
    public static List<(UnprotectedHeader, Key)> AsKeys<Key>(this List<(UnprotectedHeader, object)> list)
    {
        return list.Select(x => x.AsKey<Key>()).ToList();
    }

    public static (UnprotectedHeader, Key) AsKey<Key>(this (UnprotectedHeader, object) pair)
    {
        if (!(pair.Item2 is Key))
        {
            throw new ArgumentException($"Can not cast JWK to {typeof(Key).Name}");
        }
        return (pair.Item1, (Key)pair.Item2);
    }
}