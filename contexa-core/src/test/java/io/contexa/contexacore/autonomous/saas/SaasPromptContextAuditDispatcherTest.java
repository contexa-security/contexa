package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasPromptContextAuditHttpClient;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpServerErrorException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SaasPromptContextAuditDispatcherTest {

    private PromptContextAuditForwardingOutboxRepository repository;
    private SaasPromptContextAuditHttpClient httpClient;
    private SaasPromptContextAuditDispatcher dispatcher;

    @BeforeEach
    void setUp() {
        repository = mock(PromptContextAuditForwardingOutboxRepository.class);
        httpClient = mock(SaasPromptContextAuditHttpClient.class);
        dispatcher = new SaasPromptContextAuditDispatcher(repository, httpClient, SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .maxRetryAttempts(3)
                .retryInitialBackoffMs(1000L)
                .retryMaxBackoffMs(5000L)
                .outboxBatchSize(20)
                .build());
    }

    @Test
    void dispatchMarksRecordDeliveredOnSuccess() {
        PromptContextAuditForwardingOutboxRecord record = record();
        when(repository.findById(1L)).thenReturn(Optional.of(record));
        when(repository.save(any(PromptContextAuditForwardingOutboxRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(httpClient).send(anyString(), anyString());

        dispatcher.dispatch(1L);

        ArgumentCaptor<PromptContextAuditForwardingOutboxRecord> captor = ArgumentCaptor.forClass(PromptContextAuditForwardingOutboxRecord.class);
        verify(repository, times(2)).save(captor.capture());
        PromptContextAuditForwardingOutboxRecord delivered = captor.getAllValues().get(1);
        assertThat(delivered.getStatus()).isEqualTo(PromptContextAuditForwardingOutboxRecord.STATUS_DELIVERED);
        assertThat(delivered.getDeliveredAt()).isNotNull();
    }

    @Test
    void dispatchSchedulesRetryOnServerError() {
        PromptContextAuditForwardingOutboxRecord record = record();
        when(repository.findById(1L)).thenReturn(Optional.of(record));
        when(repository.save(any(PromptContextAuditForwardingOutboxRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doThrow(new HttpServerErrorException(HttpStatus.BAD_GATEWAY)).when(httpClient).send(anyString(), anyString());

        dispatcher.dispatch(1L);

        ArgumentCaptor<PromptContextAuditForwardingOutboxRecord> captor = ArgumentCaptor.forClass(PromptContextAuditForwardingOutboxRecord.class);
        verify(repository, times(2)).save(captor.capture());
        PromptContextAuditForwardingOutboxRecord failed = captor.getAllValues().get(1);
        assertThat(failed.getStatus()).isEqualTo(PromptContextAuditForwardingOutboxRecord.STATUS_FAILED);
        assertThat(failed.getNextAttemptAt()).isNotNull();
    }

    @Test
    void dispatchPendingBatchLoadsDispatchableRecords() {
        when(repository.findDispatchable(anyList(), any(LocalDateTime.class), any(Pageable.class))).thenReturn(List.of());

        dispatcher.dispatchPendingBatch();

        verify(repository).findDispatchable(anyList(), any(LocalDateTime.class), any(Pageable.class));
    }

    private PromptContextAuditForwardingOutboxRecord record() {
        return PromptContextAuditForwardingOutboxRecord.builder()
                .id(1L)
                .auditId("audit-001")
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{\"auditId\":\"audit-001\"}")
                .status(PromptContextAuditForwardingOutboxRecord.STATUS_PENDING)
                .attemptCount(0)
                .createdAt(LocalDateTime.now())
                .build();
    }
}