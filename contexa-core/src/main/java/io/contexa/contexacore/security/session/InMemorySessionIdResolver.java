package io.contexa.contexacore.security.session;

import io.contexa.contexacore.properties.SecuritySessionProperties;

/**
 * In-memory implementation of SessionIdResolver for standalone mode.
 * Resolves session IDs from request without Redis validation.
 * Spring Session manages session validity internally.
 */
public class InMemorySessionIdResolver extends AbstractSessionIdResolver {

    public InMemorySessionIdResolver(SecuritySessionProperties sessionProperties) {
        super(sessionProperties);
    }

    @Override
    protected boolean validateSession(String sessionId) {
        return true;
    }

    @Override
    protected String[] getSessionAttributeNames() {
        return new String[]{"CONTEXA_SESSION_ID"};
    }
}
