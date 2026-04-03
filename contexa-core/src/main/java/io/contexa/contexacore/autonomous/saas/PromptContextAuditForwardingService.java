package io.contexa.contexacore.autonomous.saas;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.mapper.PromptContextAuditPayloadMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.concurrent.Executor;

public class PromptContextAuditForwardingService {

    private final PromptContextAuditForwardingOutboxRepository repository;
    private final PromptContextAuditPayloadMapper payloadMapper;
    private final ObjectMapper objectMapper;
    private final SaasPromptContextAuditDispatcher dispatcher;
    private final Executor executor;

    public PromptContextAuditForwardingService(
            PromptContextAuditForwardingOutboxRepository repository,
            PromptContextAuditPayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasPromptContextAuditDispatcher dispatcher,
            Executor executor) {
        this.repository = repository;
        this.payloadMapper = payloadMapper;
        this.objectMapper = objectMapper;
        this.dispatcher = dispatcher;
        this.executor = executor;
    }

    public void capture(SecurityEvent event, String retrievalPurpose, AuthorizedPromptContext authorizedPromptContext) {
        PromptContextAuditPayload payload = payloadMapper.map(event, retrievalPurpose, authorizedPromptContext);
        repository.findByAuditId(payload.getAuditId()).ifPresentOrElse(
                existing -> updateAndDispatch(existing, payload),
                () -> saveAndDispatch(event, payload));
    }

    public void enrich(SecurityEvent event) {
        if (event == null) {
            return;
        }
        String correlationId = payloadMapper.resolveCorrelationId(event);
        if (!StringUtils.hasText(correlationId)) {
            return;
        }
        repository.findByCorrelationId(correlationId.trim()).ifPresent(existing -> {
            PromptContextAuditPayload current = readPayload(existing.getPayloadJson());
            PromptContextAuditPayload enriched = payloadMapper.enrich(current, event);
            updateAndDispatch(existing, enriched);
        });
    }

    private void saveAndDispatch(SecurityEvent event, PromptContextAuditPayload payload) {
        LocalDateTime now = LocalDateTime.now();
        PromptContextAuditForwardingOutboxRecord saved = repository.saveAndFlush(PromptContextAuditForwardingOutboxRecord.builder()
                .auditId(payload.getAuditId())
                .correlationId(payload.getCorrelationId())
                .tenantExternalRef(StringUtils.hasText(payload.getTenantExternalRef())
                        ? payload.getTenantExternalRef()
                        : payloadMapper.resolveTenantExternalRef(event))
                .payloadJson(writePayload(payload))
                .status(PromptContextAuditForwardingOutboxRecord.STATUS_PENDING)
                .createdAt(now)
                .updatedAt(now)
                .build());
        dispatchAsync(saved.getId());
    }

    private void updateAndDispatch(PromptContextAuditForwardingOutboxRecord existing, PromptContextAuditPayload payload) {
        String serializedPayload = writePayload(payload);
        boolean payloadChanged = !serializedPayload.equals(existing.getPayloadJson());
        if (payloadChanged) {
            if (StringUtils.hasText(payload.getCorrelationId())) {
                existing.setCorrelationId(payload.getCorrelationId().trim());
            }
            if (StringUtils.hasText(payload.getTenantExternalRef())) {
                existing.setTenantExternalRef(payload.getTenantExternalRef().trim());
            }
            existing.setPayloadJson(serializedPayload);
            existing.setStatus(PromptContextAuditForwardingOutboxRecord.STATUS_PENDING);
            existing.setNextAttemptAt(null);
            existing.setLastError(null);
            existing.setDeliveredAt(null);
            repository.saveAndFlush(existing);
        }
        dispatchAsync(existing.getId());
    }

    private void dispatchAsync(Long outboxId) {
        executor.execute(() -> dispatcher.dispatch(outboxId));
    }

    private PromptContextAuditPayload readPayload(String payloadJson) {
        if (!StringUtils.hasText(payloadJson)) {
            throw new IllegalStateException("Prompt context audit payload is empty");
        }
        try {
            return objectMapper.readValue(payloadJson, PromptContextAuditPayload.class);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize prompt context audit payload", e);
        }
    }

    private String writePayload(PromptContextAuditPayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize prompt context audit payload", e);
        }
    }
}