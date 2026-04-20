package io.contexa.contexacore.hcad.store;

import java.time.Duration;

class InMemoryBaselineDataStoreContractTest extends AbstractBaselineDataStoreContractTest {

    @Override
    protected BaselineDataStore createStore() {
        return new InMemoryBaselineDataStore();
    }

    @Override
    protected BaselineDataStore createStoreWithTtl(Duration ttl) {
        return new InMemoryBaselineDataStore(ttl);
    }
}
