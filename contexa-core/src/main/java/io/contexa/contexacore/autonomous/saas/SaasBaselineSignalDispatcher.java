package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasBaselineSignalHttpClient;
import io.contexa.contexacore.domain.entity.BaselineSignalOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.BaselineSignalOutboxRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;

import java.time.Clock;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.TemporalAdjusters;
import java.util.List;

public class SaasBaselineSignalDispatcher {

    private static final List<String> DISPATCHABLE_STATUSES = List.of(
            BaselineSignalOutboxRecord.STATUS_PENDING,
            BaselineSignalOutboxRecord.STATUS_FAILED);

    private final BaselineSignalOutboxRepository repository;
    private final SaasBaselineSignalHttpClient httpClient;
    private final SaasForwardingProperties properties;
    private final Clock clock;

    public SaasBaselineSignalDispatcher(
            BaselineSignalOutboxRepository repository,
            SaasBaselineSignalHttpClient httpClient,
            SaasForwardingProperties properties) {
        this(repository, httpClient, properties, Clock.systemDefaultZone());
    }

    SaasBaselineSignalDispatcher(
            BaselineSignalOutboxRepository repository,
            SaasBaselineSignalHttpClient httpClient,
            SaasForwardingProperties properties,
            Clock clock) {
        this.repository = repository;
        this.httpClient = httpClient;
        this.properties = properties;
        this.clock = clock;
    }

    public void dispatchPendingBatch() {
        int batchSize = Math.max(1, properties.getOutboxBatchSize());
        List<BaselineSignalOutboxRecord> batch = repository.findDispatchableCompleted(
                DISPATCHABLE_STATUSES,
                currentPeriodStart(),
                LocalDateTime.now(clock),
                PageRequest.of(0, batchSize));
        for (BaselineSignalOutboxRecord record : batch) {
            doDispatch(record);
        }
    }

    private void doDispatch(BaselineSignalOutboxRecord record) {
        record.markDispatching();
        repository.save(record);
        try {
            httpClient.send(record.toPayload());
            record.markDelivered(LocalDateTime.now(clock));
        } catch (HttpClientErrorException exception) {
            if (exception.getStatusCode().value() == 429) {
                scheduleRetry(record, exception);
            } else {
                record.markDeadLetter(errorMessage(exception));
            }
        } catch (HttpServerErrorException | ResourceAccessException exception) {
            scheduleRetry(record, exception);
        } catch (RestClientResponseException exception) {
            scheduleRetry(record, exception);
        } catch (Exception exception) {
            scheduleRetry(record, exception);
        }
        repository.save(record);
    }

    private void scheduleRetry(BaselineSignalOutboxRecord record, Exception exception) {
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

    private LocalDate currentPeriodStart() {
        return LocalDate.now(clock).with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
    }

    private String errorMessage(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return exception.getClass().getSimpleName();
        }
        return message;
    }
}
