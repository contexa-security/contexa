package io.contexa.contexacore.hcad.store;

import java.time.Duration;

class InMemoryHCADDataStoreContractTest extends AbstractHCADDataStoreContractTest {

    @Override
    protected HCADDataStore createStore() {
        return new InMemoryHCADDataStore();
    }

    @Override
    protected HCADDataStore createStoreWithMfaTtl(Duration mfaVerifiedTtl) {
        return new InMemoryHCADDataStore(mfaVerifiedTtl);
    }
}
