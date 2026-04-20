package io.contexa.contexacore.security.session;

import io.contexa.contexacore.properties.SecuritySessionProperties;

import java.util.UUID;

class InMemorySessionIdResolverContractTest extends AbstractSessionIdResolverContractTest {

    @Override
    protected SessionIdResolver createResolver() {
        return new InMemorySessionIdResolver(new SecuritySessionProperties());
    }

    @Override
    protected String anActiveSessionId() {
        return UUID.randomUUID().toString();
    }
}
