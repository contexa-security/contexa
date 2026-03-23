package io.contexa.contexacore.autonomous.saas;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.mapper.SecurityDecisionForwardingPayloadMapper;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;

import java.util.Map;
import java.util.concurrent.Executor;

public class SaasDecisionOutboxService {

    private final SecurityDecisionForwardingOutboxRepository repository;
    private final SecurityDecisionForwardingPayloadMapper payloadMapper;
    private final ObjectMapper objectMapper;
    private final SaasDecisionDispatcher dispatcher;
    private final Executor executor;

    public SaasDecisionOutboxService(
            SecurityDecisionForwardingOutboxRepository repository,
            SecurityDecisionForwardingPayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasDecisionDispatcher dispatcher,
            Executor executor) {
        this.repository = repository;
        this.payloadMapper = payloadMapper;
        this.objectMapper = objectMapper;
        this.dispatcher = dispatcher;
        this.executor = executor;
    }

    public void capture(SecurityEventContext context) {
        SecurityDecisionForwardingPayload payload = payloadMapper.map(context);
        repository.findByCorrelationId(payload.getCorrelationId()).ifPresentOrElse(
                existing -> dispatchAsync(existing.getId()),
                () -> saveAndDispatch(context.getSecurityEvent(), payload));
    }

    private void saveAndDispatch(SecurityEvent event, SecurityDecisionForwardingPayload payload) {
        SecurityDecisionForwardingOutboxRecord saved = repository.saveAndFlush(SecurityDecisionForwardingOutboxRecord.builder()
                .correlationId(payload.getCorrelationId())
                .tenantExternalRef(resolveTenantExternalRef(event))
                .payloadJson(writePayload(payload))
                .status(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING)
                .build());
        dispatchAsync(saved.getId());
    }

    private void dispatchAsync(Long outboxId) {
        executor.execute(() -> dispatcher.dispatch(outboxId));
    }

    private String resolveTenantExternalRef(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object tenantId = metadata.get("tenantId");
            if (tenantId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
            Object organizationId = metadata.get("organizationId");
            if (organizationId instanceof String value && !value.isBlank()) {
                return value.trim();
            }
        }
        return "default";
    }

    private String writePayload(SecurityDecisionForwardingPayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize SaaS decision forwarding payload", e);
        }
    }
}
