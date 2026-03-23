package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasDecisionHttpClient;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SaasDecisionDispatcherTest {

    private SecurityDecisionForwardingOutboxRepository repository;
    private SaasDecisionHttpClient httpClient;
    private SaasForwardingProperties properties;
    private SaasDecisionDispatcher dispatcher;

    @BeforeEach
    void setUp() {
        repository = mock(SecurityDecisionForwardingOutboxRepository.class);
        httpClient = mock(SaasDecisionHttpClient.class);
        properties = SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .pseudonymizationSecret("top-secret-key")
                .globalCorrelationSecret("global-correlation-secret")
                .maxRetryAttempts(3)
                .retryInitialBackoffMs(1000L)
                .retryMaxBackoffMs(5000L)
                .outboxBatchSize(50)
                .oauth2(SaasForwardingProperties.OAuth2.builder()
                        .enabled(true)
                        .registrationId("reg")
                        .tokenUri("https://auth.example.com/oauth2/token")
                        .clientId("client")
                        .clientSecret("secret")
                        .scope("saas.xai.decision.ingest")
                        .expirySkewSeconds(30)
                        .build())
                .build();
        dispatcher = new SaasDecisionDispatcher(repository, httpClient, properties);
    }

    @Test
    void dispatchMarksRecordDeliveredOnSuccess() {
        SecurityDecisionForwardingOutboxRecord record = record();
        when(repository.findById(1L)).thenReturn(Optional.of(record));
        when(repository.save(any(SecurityDecisionForwardingOutboxRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doNothing().when(httpClient).send(anyString(), anyString());

        dispatcher.dispatch(1L);

        ArgumentCaptor<SecurityDecisionForwardingOutboxRecord> captor = ArgumentCaptor.forClass(SecurityDecisionForwardingOutboxRecord.class);
        verify(repository, times(2)).save(captor.capture());
        List<SecurityDecisionForwardingOutboxRecord> saved = captor.getAllValues();
        assertThat(saved.get(1).getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_DELIVERED);
        assertThat(saved.get(1).getDeliveredAt()).isNotNull();
    }

    @Test
    void dispatchSchedulesRetryOnServerError() {
        SecurityDecisionForwardingOutboxRecord record = record();
        when(repository.findById(1L)).thenReturn(Optional.of(record));
        when(repository.save(any(SecurityDecisionForwardingOutboxRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doThrow(new HttpServerErrorException(HttpStatus.BAD_GATEWAY)).when(httpClient).send(anyString(), anyString());

        dispatcher.dispatch(1L);

        ArgumentCaptor<SecurityDecisionForwardingOutboxRecord> captor = ArgumentCaptor.forClass(SecurityDecisionForwardingOutboxRecord.class);
        verify(repository, times(2)).save(captor.capture());
        SecurityDecisionForwardingOutboxRecord failed = captor.getAllValues().get(1);
        assertThat(failed.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_FAILED);
        assertThat(failed.getNextAttemptAt()).isNotNull();
    }

    @Test
    void dispatchMovesRecordToDeadLetterOnNonRetryableClientError() {
        SecurityDecisionForwardingOutboxRecord record = record();
        when(repository.findById(1L)).thenReturn(Optional.of(record));
        when(repository.save(any(SecurityDecisionForwardingOutboxRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        doThrow(HttpClientErrorException.create(
                HttpStatus.FORBIDDEN,
                "Forbidden",
                HttpHeaders.EMPTY,
                new byte[0],
                StandardCharsets.UTF_8)).when(httpClient).send(anyString(), anyString());

        dispatcher.dispatch(1L);

        ArgumentCaptor<SecurityDecisionForwardingOutboxRecord> captor = ArgumentCaptor.forClass(SecurityDecisionForwardingOutboxRecord.class);
        verify(repository, times(2)).save(captor.capture());
        SecurityDecisionForwardingOutboxRecord failed = captor.getAllValues().get(1);
        assertThat(failed.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_DEAD_LETTER);
    }

    @Test
    void dispatchPendingBatchLoadsDispatchableRecords() {
        when(repository.findDispatchable(anyList(), any(LocalDateTime.class), any(Pageable.class))).thenReturn(List.of());

        dispatcher.dispatchPendingBatch();

        verify(repository).findDispatchable(anyList(), any(LocalDateTime.class), any(Pageable.class));
    }

    private SecurityDecisionForwardingOutboxRecord record() {
        return SecurityDecisionForwardingOutboxRecord.builder()
                .id(1L)
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{\"correlationId\":\"corr-001\"}")
                .status(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING)
                .attemptCount(0)
                .createdAt(LocalDateTime.now())
                .build();
    }
}
