package io.contexa.contexacore.autonomous.context.enricher;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

/**
 * Common interface for all context enrichment providers.
 * Enriches CanonicalSecurityContext with domain-specific data from SecurityEvent.
 */
public interface ContextEnricher {

    void enrich(SecurityEvent event, CanonicalSecurityContext context);
}
