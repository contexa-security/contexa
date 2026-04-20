package io.contexa.contexacore.autonomous.repository;

import java.time.Duration;

class InMemoryZeroTrustActionRepositoryFailCountContractTest
        extends AbstractZeroTrustActionRepositoryFailCountContractTest {

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new InMemoryZeroTrustActionRepository();
    }

    @Override
    protected ZeroTrustActionRepository createRepositoryWithFailCountTtl(Duration failCountTtl) {
        return new InMemoryZeroTrustActionRepository(failCountTtl);
    }
}
