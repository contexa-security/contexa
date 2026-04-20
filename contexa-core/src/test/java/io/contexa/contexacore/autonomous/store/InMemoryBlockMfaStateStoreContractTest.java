package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;

import java.time.Duration;

class InMemoryBlockMfaStateStoreContractTest extends AbstractBlockMfaStateStoreContractTest {

    @Override
    protected BlockMfaStateStore createStore(ZeroTrustActionRepository actionRepository) {
        return new InMemoryBlockMfaStateStore(actionRepository);
    }

    @Override
    protected BlockMfaStateStore createStoreWithVerifiedTtl(ZeroTrustActionRepository actionRepository,
                                                            Duration verifiedTtl) {
        return new InMemoryBlockMfaStateStore(actionRepository, verifiedTtl);
    }
}
