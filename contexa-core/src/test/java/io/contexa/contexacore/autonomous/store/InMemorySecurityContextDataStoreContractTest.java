package io.contexa.contexacore.autonomous.store;

import java.time.Duration;

class InMemorySecurityContextDataStoreContractTest extends AbstractSecurityContextDataStoreContractTest {

    @Override
    protected SecurityContextDataStore createStore() {
        return new InMemorySecurityContextDataStore();
    }

    @Override
    protected SecurityContextDataStore createStoreWithEventProcessedTtl(Duration ttl) {
        return new InMemorySecurityContextDataStore(
                ttl,
                Duration.ofDays(7),
                Duration.ofDays(7));
    }
}
