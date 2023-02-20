namespace Blocktrust.DIDComm.Tests.Utils;

using DIDComm.Utils;

public class DIDUtilsTest
{
    [Fact]
    public void CalculateApv()
    {
        Assert.Equal(
            "_Xzta7iZsfJXb_-2CaL6LCzZJOKmfYzPnGZ5-52RtK0",
            DidUtils.CalculateApv(
                new List<string> { "key1", "key2" }
            ).ToString()
        );
    }

    [Fact]
    public void CalculateApvOrderIndependent()
    {
        Assert.Equal(
            DidUtils.CalculateApv(new List<string> { "key1", "key2" }),
            DidUtils.CalculateApv(new List<string> { "key2", "key1" })
        );
    }

    [Fact]
    public void IsDid()
    {
        Assert.True(DidUtils.IsDid("did:example:alice"));
        Assert.True(DidUtils.IsDid("did:example:alice:alice2"));
        Assert.True(DidUtils.IsDid("did:example:alice#key-1"));
        Assert.True(DidUtils.IsDid("did:example:alice:alice2#key-1"));

        Assert.False(DidUtils.IsDid("did:example"));
        Assert.False(DidUtils.IsDid("did"));
        Assert.False(DidUtils.IsDid("did:example#key-1"));
    }
}