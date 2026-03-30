package io.contexa.contexacore.autonomous.saas;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import io.contexa.contexacore.autonomous.saas.mapper.ThreatOutcomePayloadMapper;
import io.contexa.contexacore.domain.entity.ThreatOutcomeForwardingOutboxRecord;
import io.contexa.contexacore.repository.ThreatOutcomeForwardingOutboxRepository;

import java.time.LocalDateTime;
import java.util.concurrent.Executor;

public class SaasThreatOutcomeOutboxService implements ThreatOutcomeForwardingService {

    private final ThreatOutcomeForwardingOutboxRepository repository;
    private final ThreatOutcomePayloadMapper payloadMapper;
    private final ObjectMapper objectMapper;
    private final SaasThreatOutcomeDispatcher dispatcher;
    private final Executor executor;

    public SaasThreatOutcomeOutboxService(
            ThreatOutcomeForwardingOutboxRepository repository,
            ThreatOutcomePayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasThreatOutcomeDispatcher dispatcher,
            Executor executor) {
        this.repository = repository;
        this.payloadMapper = payloadMapper;
        this.objectMapper = objectMapper;
        this.dispatcher = dispatcher;
        this.executor = executor;
    }

    @Override
    public void capture(AdminOverride adminOverride, SecurityEvent originalEvent) {
        ThreatOutcomePayload payload = payloadMapper.map(adminOverride, originalEvent);
        repository.findByOutcomeId(payload.getOutcomeId()).ifPresentOrElse(
                existing -> dispatchAsync(existing.getId()),
                () -> saveAndDispatch(payload, originalEvent));
    }

    private void saveAndDispatch(ThreatOutcomePayload payload, SecurityEvent originalEvent) {
        LocalDateTime now = LocalDateTime.now();
        ThreatOutcomeForwardingOutboxRecord saved = repository.saveAndFlush(ThreatOutcomeForwardingOutboxRecord.builder()
                .outcomeId(payload.getOutcomeId())
                .correlationId(payload.getCorrelationId())
                .tenantExternalRef(payloadMapper.resolveTenantExternalRef(originalEvent))
                .payloadJson(writePayload(payload))
                .status(ThreatOutcomeForwardingOutboxRecord.STATUS_PENDING)
                .createdAt(now)
                .updatedAt(now)
                .build());
        dispatchAsync(saved.getId());
    }

    private void dispatchAsync(Long outboxId) {
        executor.execute(() -> dispatcher.dispatch(outboxId));
    }

    private String writePayload(ThreatOutcomePayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize SaaS threat outcome payload", e);
        }
    }
}
