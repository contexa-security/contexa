package io.contexa.contexacore.autonomous.saas;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.saas.dto.SecurityDecisionForwardingPayload;
import io.contexa.contexacore.autonomous.saas.mapper.SecurityDecisionForwardingPayloadMapper;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
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
class SaasDecisionOutboxServiceTest {

    @Mock
    private SecurityDecisionForwardingOutboxRepository repository;

    @Mock
    private SecurityDecisionForwardingPayloadMapper payloadMapper;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private SaasDecisionDispatcher dispatcher;

    private SaasDecisionOutboxService service;

    @BeforeEach
    void setUp() {
        Executor executor = Runnable::run;
        service = new SaasDecisionOutboxService(repository, payloadMapper, objectMapper, dispatcher, executor);
    }

    @Test
    void captureSavesNewOutboxRecordWithTimestamps() throws Exception {
        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-001")
                .metadata(Map.of("tenantId", "tenant-acme"))
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        SecurityDecisionForwardingPayload payload = SecurityDecisionForwardingPayload.builder()
                .correlationId("corr-001")
                .decision("CHALLENGE")
                .build();
        when(payloadMapper.map(context)).thenReturn(payload);
        when(repository.findByCorrelationId("corr-001")).thenReturn(Optional.empty());
        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"correlationId\":\"corr-001\"}");
        when(repository.saveAndFlush(any(SecurityDecisionForwardingOutboxRecord.class))).thenAnswer(invocation -> {
            SecurityDecisionForwardingOutboxRecord saved = invocation.getArgument(0);
            saved.setId(31L);
            return saved;
        });

        service.capture(context);

        ArgumentCaptor<SecurityDecisionForwardingOutboxRecord> captor = ArgumentCaptor.forClass(SecurityDecisionForwardingOutboxRecord.class);
        verify(repository).saveAndFlush(captor.capture());
        SecurityDecisionForwardingOutboxRecord saved = captor.getValue();
        assertThat(saved.getCorrelationId()).isEqualTo("corr-001");
        assertThat(saved.getTenantExternalRef()).isEqualTo("tenant-acme");
        assertThat(saved.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING);
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        verify(dispatcher).dispatch(31L);
    }
}
