package io.contexa.contexacore.autonomous.saas;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.mapper.DecisionFeedbackPayloadMapper;
import io.contexa.contexacore.domain.entity.DecisionFeedbackForwardingOutboxRecord;
import io.contexa.contexacore.repository.DecisionFeedbackForwardingOutboxRepository;

import java.util.concurrent.Executor;

public class SaasDecisionFeedbackOutboxService implements DecisionFeedbackForwardingService {

    private final DecisionFeedbackForwardingOutboxRepository repository;
    private final DecisionFeedbackPayloadMapper payloadMapper;
    private final ObjectMapper objectMapper;
    private final SaasDecisionFeedbackDispatcher dispatcher;
    private final Executor executor;

    public SaasDecisionFeedbackOutboxService(
            DecisionFeedbackForwardingOutboxRepository repository,
            DecisionFeedbackPayloadMapper payloadMapper,
            ObjectMapper objectMapper,
            SaasDecisionFeedbackDispatcher dispatcher,
            Executor executor) {
        this.repository = repository;
        this.payloadMapper = payloadMapper;
        this.objectMapper = objectMapper;
        this.dispatcher = dispatcher;
        this.executor = executor;
    }

    @Override
    public void capture(AdminOverride adminOverride, SecurityEvent originalEvent) {
        DecisionFeedbackPayload payload = payloadMapper.map(adminOverride, originalEvent);
        repository.findByFeedbackId(payload.getFeedbackId()).ifPresentOrElse(
                existing -> dispatchAsync(existing.getId()),
                () -> saveAndDispatch(payload, originalEvent));
    }

    private void saveAndDispatch(DecisionFeedbackPayload payload, SecurityEvent originalEvent) {
        DecisionFeedbackForwardingOutboxRecord saved = repository.saveAndFlush(DecisionFeedbackForwardingOutboxRecord.builder()
                .feedbackId(payload.getFeedbackId())
                .correlationId(payload.getCorrelationId())
                .tenantExternalRef(payloadMapper.resolveTenantExternalRef(originalEvent))
                .payloadJson(writePayload(payload))
                .status(DecisionFeedbackForwardingOutboxRecord.STATUS_PENDING)
                .build());
        dispatchAsync(saved.getId());
    }

    private void dispatchAsync(Long outboxId) {
        executor.execute(() -> dispatcher.dispatch(outboxId));
    }

    private String writePayload(DecisionFeedbackPayload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize SaaS decision feedback payload", e);
        }
    }
}
