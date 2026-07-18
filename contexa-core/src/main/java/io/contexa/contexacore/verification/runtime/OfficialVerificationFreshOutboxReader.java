package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;

import java.time.Duration;
import java.util.Optional;

/**
 * Transport-neutral read port for fresh verification outbox evidence.
 */
public interface OfficialVerificationFreshOutboxReader {

    Optional<SecurityDecisionForwardingOutboxRecord> findFreshDecisionOutbox(String correlationId);

    Optional<PromptContextAuditForwardingOutboxRecord> findFreshPromptAuditOutbox(String correlationId);

    Optional<PromptContextAuditForwardingOutboxRecord> awaitPromptAuditOutbox(
            String correlationId,
            Duration timeout,
            boolean requireLineage);
}