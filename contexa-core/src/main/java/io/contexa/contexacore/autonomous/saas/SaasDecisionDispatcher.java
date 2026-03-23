package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasDecisionHttpClient;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;

import java.time.LocalDateTime;
import java.util.List;

public class SaasDecisionDispatcher {

    private static final List<String> DISPATCHABLE_STATUSES = List.of(
            SecurityDecisionForwardingOutboxRecord.STATUS_PENDING,
            SecurityDecisionForwardingOutboxRecord.STATUS_FAILED);

    private final SecurityDecisionForwardingOutboxRepository repository;
    private final SaasDecisionHttpClient httpClient;
    private final SaasForwardingProperties properties;

    public SaasDecisionDispatcher(
            SecurityDecisionForwardingOutboxRepository repository,
            SaasDecisionHttpClient httpClient,
            SaasForwardingProperties properties) {
        this.repository = repository;
        this.httpClient = httpClient;
        this.properties = properties;
    }

    public void dispatch(Long outboxId) {
        SecurityDecisionForwardingOutboxRecord record = repository.findById(outboxId).orElse(null);
        if (record == null || SecurityDecisionForwardingOutboxRecord.STATUS_DELIVERED.equals(record.getStatus())
                || SecurityDecisionForwardingOutboxRecord.STATUS_DEAD_LETTER.equals(record.getStatus())) {
            return;
        }
        doDispatch(record);
    }

    public void dispatchPendingBatch() {
        int batchSize = Math.max(1, properties.getOutboxBatchSize());
        List<SecurityDecisionForwardingOutboxRecord> batch = repository.findDispatchable(
                DISPATCHABLE_STATUSES,
                LocalDateTime.now(),
                PageRequest.of(0, batchSize));
        for (SecurityDecisionForwardingOutboxRecord record : batch) {
            doDispatch(record);
        }
    }

    private void doDispatch(SecurityDecisionForwardingOutboxRecord record) {
        record.markDispatching();
        repository.save(record);
        try {
            httpClient.send(record.getCorrelationId(), record.getPayloadJson());
            record.markDelivered(LocalDateTime.now());
        }
        catch (HttpClientErrorException exception) {
            if (exception.getStatusCode().value() == 429) {
                scheduleRetry(record, exception);
            }
            else {
                record.markDeadLetter(errorMessage(exception));
            }
        }
        catch (HttpServerErrorException | ResourceAccessException exception) {
            scheduleRetry(record, exception);
        }
        catch (RestClientResponseException exception) {
            scheduleRetry(record, exception);
        }
        catch (Exception exception) {
            scheduleRetry(record, exception);
        }
        repository.save(record);
    }

    private void scheduleRetry(SecurityDecisionForwardingOutboxRecord record, Exception exception) {
        int attemptCount = record.getAttemptCount() == null ? 1 : record.getAttemptCount();
        if (attemptCount >= properties.getMaxRetryAttempts()) {
            record.markDeadLetter(errorMessage(exception));
            return;
        }
        long backoff = computeBackoffMillis(attemptCount);
        record.markRetry(errorMessage(exception), LocalDateTime.now().plusNanos(backoff * 1_000_000L));
    }

    private long computeBackoffMillis(int attemptCount) {
        long initial = Math.max(1_000L, properties.getRetryInitialBackoffMs());
        long max = Math.max(initial, properties.getRetryMaxBackoffMs());
        long computed = initial * (1L << Math.max(0, attemptCount - 1));
        return Math.min(computed, max);
    }

    private String errorMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return exception.getClass().getSimpleName();
        }
        return message;
    }
}
