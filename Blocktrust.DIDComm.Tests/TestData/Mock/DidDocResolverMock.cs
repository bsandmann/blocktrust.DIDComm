namespace Blocktrust.DIDComm.Tests.TestData.Mock;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;
using DIDDoc;
using DidDocs;

public class DidDocResolverMock : IDidDocResolver
{
    private DidDocResolverInMemory _didDocResolver;

    public DidDocResolverMock()
    {
        _didDocResolver = new DidDocResolverInMemory(new List<DidDoc>()
        {
            DIDDocAlice.DID_DOC_ALICE_SPEC_TEST_VECTORS,
            DIDDocBob.DID_DOC_BOB_SPEC_TEST_VECTORS,
            DIDDocCharlie.DID_DOC_CHARLIE,
            DIDDocMediator1.DID_DOC_MEDIATOR1,
            DIDDocMediator2.DID_DOC_MEDIATOR2,
            DIDDocEllie.DID_DOC_ELLIE
        });
    }

    public DidDoc? Resolve(String did)
    {
        return _didDocResolver.Resolve(did);
    }
}