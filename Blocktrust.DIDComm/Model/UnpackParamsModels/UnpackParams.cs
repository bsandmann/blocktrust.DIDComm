namespace Blocktrust.DIDComm.Model.UnpackParamsModels;

using Blocktrust.Common.Resolver;

public class UnpackParams
{
    public string PackedMessage { get; private set; }
    public bool ExpectDecryptByAllKeys { get; private set; }
    public bool UnwrapReWrappingForward { get; private set; }
    public IDidDocResolver IdidDocResolver { get; private set; }
    public ISecretResolver SecretResolver { get; private set; }

    public UnpackParams(string packedMessage, bool expectDecryptByAllKeys, bool unwrapReWrappingForward, IDidDocResolver ididDocResolver, ISecretResolver secretResolver)
    {
        this.PackedMessage = packedMessage;
        this.ExpectDecryptByAllKeys = expectDecryptByAllKeys;
        this.UnwrapReWrappingForward = unwrapReWrappingForward;
        this.IdidDocResolver = ididDocResolver;
        this.SecretResolver = secretResolver;
    }

    public UnpackParams(UnpackParamsBuilder unpackParamsBuilder) : this(
        unpackParamsBuilder.PackedMessage,
        unpackParamsBuilder.expectDecryptByAllKeys,
        unpackParamsBuilder.unwrapReWrappingForward,
        unpackParamsBuilder.didDocResolver,
        unpackParamsBuilder.secretResolver
    )
    {
    }
}
