namespace Blocktrust.DIDComm.Model.UnpackParamsModels;

using Blocktrust.Common.Resolver;

public class UnpackParamsBuilder
{
    public string PackedMessage;

    internal bool expectDecryptByAllKeys = false;
    internal bool unwrapReWrappingForward = true;
    internal IDidDocResolver? didDocResolver;
    internal ISecretResolver? secretResolver;


    public UnpackParamsBuilder()
    {
        
    }

    public UnpackParamsBuilder(string packedMessage)
    {
        this.PackedMessage = packedMessage;
    }

    public UnpackParamsBuilder ExpectDecryptByAllKeys(bool expectDecryptByAllKeys)
    {
        this.expectDecryptByAllKeys = expectDecryptByAllKeys;
        return this;
    }

    public UnpackParamsBuilder UnwrapReWrappingForward(bool unwrapReWrappingForward)
    {
        this.unwrapReWrappingForward = unwrapReWrappingForward;
        return this;
    }

    public UnpackParamsBuilder DidDocResolver(IDidDocResolver ididDocResolver)
    {
        this.didDocResolver = ididDocResolver;
        return this;
    }

    public UnpackParamsBuilder SecretResolver(ISecretResolver secretResolver)
    {
        this.secretResolver = secretResolver;
        return this;
    }

    public UnpackParams BuildUnpackParams()
    {
        return new UnpackParams(this);
    }
}