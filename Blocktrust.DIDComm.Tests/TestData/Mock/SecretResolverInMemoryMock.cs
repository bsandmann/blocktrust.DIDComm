namespace Blocktrust.DIDComm.Tests.TestData.Mock;

using Blocktrust.Common.Models.Secrets;
using Blocktrust.Common.Resolver;

public interface SecretResolverInMemoryMock : ISecretResolver
{
    List<Secret> GetSecrets();
    List<string> GetSecretKids();
}