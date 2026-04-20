package io.contexa.contexacore.autonomous.repository;

class InMemoryProtectableRapidReentryRepositoryContractTest
        extends AbstractProtectableRapidReentryRepositoryContractTest {

    @Override
    protected ProtectableRapidReentryRepository createRepository() {
        return new InMemoryProtectableRapidReentryRepository();
    }
}
