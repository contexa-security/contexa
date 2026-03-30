package io.contexa.contexacore.autonomous.saas;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.mapper.DecisionFeedbackPayloadMapper;
import io.contexa.contexacore.domain.entity.DecisionFeedbackForwardingOutboxRecord;
import io.contexa.contexacore.repository.DecisionFeedbackForwardingOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SaasDecisionFeedbackOutboxServiceTest {

    @Mock
    private DecisionFeedbackForwardingOutboxRepository repository;

    @Mock
    private DecisionFeedbackPayloadMapper payloadMapper;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private SaasDecisionFeedbackDispatcher dispatcher;

    private SaasDecisionFeedbackOutboxService service;

    @BeforeEach
    void setUp() {
        Executor executor = Runnable::run;
        service = new SaasDecisionFeedbackOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Test
    void captureSavesNewOutboxRecordWithTimestamps() throws Exception {
        AdminOverride adminOverride = AdminOverride.builder()
                .overrideId("ovr-001")
                .requestId("req-001")
                .approved(true)
                .originalRiskScore(0.9d)
                .originalConfidence(0.8d)
                .build();
        SecurityEvent originalEvent = SecurityEvent.builder()
                .eventId("evt-001")
                .metadata(Map.of("tenantId", "tenant-acme"))
                .build();
        DecisionFeedbackPayload payload = DecisionFeedbackPayload.builder()
                .feedbackId("feedback-001")
                .correlationId("corr-001")
                .build();
        when(payloadMapper.map(adminOverride, originalEvent)).thenReturn(payload);
        when(payloadMapper.resolveTenantExternalRef(originalEvent)).thenReturn("tenant-acme");
        when(repository.findByFeedbackId("feedback-001")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"feedbackId\":\"feedback-001\"}");
        when(repository.saveAndFlush(any(DecisionFeedbackForwardingOutboxRecord.class))).thenAnswer(invocation -> {
            DecisionFeedbackForwardingOutboxRecord saved = invocation.getArgument(0);
            saved.setId(51L);
            return saved;
        });

        service.capture(adminOverride, originalEvent);

        ArgumentCaptor<DecisionFeedbackForwardingOutboxRecord> captor = ArgumentCaptor.forClass(DecisionFeedbackForwardingOutboxRecord.class);
        verify(repository).saveAndFlush(captor.capture());
        DecisionFeedbackForwardingOutboxRecord saved = captor.getValue();
        assertThat(saved.getFeedbackId()).isEqualTo("feedback-001");
        assertThat(saved.getTenantExternalRef()).isEqualTo("tenant-acme");
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        verify(dispatcher).dispatch(51L);
    }
}
