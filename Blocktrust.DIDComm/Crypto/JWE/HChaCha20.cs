namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Buffers.Binary;

public static class HChaCha20
{
    public static byte[] CreateSubkey(byte[] key, byte[] nonce)
    {
        var state = CreateInitialState(key, nonce);
        PerformRounds(state);

        return FromUint32LittleEndian(new[]
        {
            state[0], state[1], state[2], state[3],
            state[12], state[13], state[14], state[15],
        }, 32);
    }

    private static byte[] FromUint32LittleEndian(uint[] input, int outputLength)
    {
        var output = new byte[outputLength];

        for (var i = 0; i < input.Length; i++)
        {
            var u = input[i];
            var temp = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(temp, u);
            Array.Copy(temp, 0, output, i * 4, temp.Length);
        }

        return output;
    }

    public static uint[] CreateInitialState(byte[] key, byte[] nonce)
    {
        var state = new uint[16];

        // set HChaCha20 constant
        var constant = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 };
        Array.Copy(constant, state, constant.Length);

        // set key
        var keyState = ToUint32LittleEndian(key, 8);
        Array.Copy(keyState, 0, state, 4, keyState.Length);

        // set nonce
        var nonceState = ToUint32LittleEndian(nonce, 4);
        Array.Copy(nonceState, 0, state, state.Length - 4, nonceState.Length);

        return state;
    }

    private static uint[] ToUint32LittleEndian(byte[] bytes, int outputLength)
    {
        var pos = 0;
        var output = new uint[outputLength];

        using (var ms = new MemoryStream(bytes))
        {
            while (pos != outputLength)
            {
                var temp = new byte[4];
                ms.Read(temp, 0, 4);
                output[pos] = BinaryPrimitives.ReadUInt32LittleEndian(temp);
                pos += 1;
            }
        }

        return output;
    }

    public static void PerformRounds(uint[] state)
    {
        for (var i = 0; i < 10; i++)
        {
            ChaCha20.QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
            ChaCha20.QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
            ChaCha20.QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
            ChaCha20.QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);
            ChaCha20.QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
            ChaCha20.QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
            ChaCha20.QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
            ChaCha20.QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
        }
    }
}