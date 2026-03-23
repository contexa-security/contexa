package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasModelPerformanceTelemetryHttpClient;
import io.contexa.contexacore.domain.entity.ModelPerformanceTelemetryOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.ModelPerformanceTelemetryOutboxRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;

import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public class SaasModelPerformanceTelemetryDispatcher {

    private static final List<String> DISPATCHABLE_STATUSES = List.of(
            ModelPerformanceTelemetryOutboxRecord.STATUS_PENDING,
            ModelPerformanceTelemetryOutboxRecord.STATUS_FAILED);

    private final ModelPerformanceTelemetryOutboxRepository repository;
    private final SaasModelPerformanceTelemetryHttpClient httpClient;
    private final SaasForwardingProperties properties;
    private final Clock clock;

    public SaasModelPerformanceTelemetryDispatcher(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasModelPerformanceTelemetryHttpClient httpClient,
            SaasForwardingProperties properties) {
        this(repository, httpClient, properties, Clock.systemDefaultZone());
    }

    SaasModelPerformanceTelemetryDispatcher(
            ModelPerformanceTelemetryOutboxRepository repository,
            SaasModelPerformanceTelemetryHttpClient httpClient,
            SaasForwardingProperties properties,
            Clock clock) {
        this.repository = repository;
        this.httpClient = httpClient;
        this.properties = properties;
        this.clock = clock;
    }

    public void dispatch(Long outboxId) {
        ModelPerformanceTelemetryOutboxRecord record = repository.findById(outboxId).orElse(null);
        if (record == null
                || ModelPerformanceTelemetryOutboxRecord.STATUS_DELIVERED.equals(record.getStatus())
                || ModelPerformanceTelemetryOutboxRecord.STATUS_DEAD_LETTER.equals(record.getStatus())
                || !isCompletedPeriod(record)) {
            return;
        }
        doDispatch(record);
    }

    public void dispatchPendingBatch() {
        int batchSize = Math.max(1, properties.getOutboxBatchSize());
        List<ModelPerformanceTelemetryOutboxRecord> batch = repository.findDispatchableCompleted(
                DISPATCHABLE_STATUSES,
                LocalDate.now(clock),
                LocalDateTime.now(clock),
                PageRequest.of(0, batchSize));
        for (ModelPerformanceTelemetryOutboxRecord record : batch) {
            doDispatch(record);
        }
    }

    private void doDispatch(ModelPerformanceTelemetryOutboxRecord record) {
        record.markDispatching();
        repository.save(record);
        try {
            httpClient.send(record.toPayload());
            record.markDelivered(LocalDateTime.now(clock));
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

    private void scheduleRetry(ModelPerformanceTelemetryOutboxRecord record, Exception exception) {
        int attemptCount = record.getAttemptCount() == null ? 1 : record.getAttemptCount();
        if (attemptCount >= properties.getMaxRetryAttempts()) {
            record.markDeadLetter(errorMessage(exception));
            return;
        }
        long backoff = computeBackoffMillis(attemptCount);
        record.markRetry(errorMessage(exception), LocalDateTime.now(clock).plusNanos(backoff * 1_000_000L));
    }

    private long computeBackoffMillis(int attemptCount) {
        long initial = Math.max(1_000L, properties.getRetryInitialBackoffMs());
        long max = Math.max(initial, properties.getRetryMaxBackoffMs());
        long computed = initial * (1L << Math.max(0, attemptCount - 1));
        return Math.min(computed, max);
    }

    private boolean isCompletedPeriod(ModelPerformanceTelemetryOutboxRecord record) {
        return record.getPeriod() != null && record.getPeriod().isBefore(LocalDate.now(clock));
    }

    private String errorMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return exception.getClass().getSimpleName();
        }
        return message;
    }
}
