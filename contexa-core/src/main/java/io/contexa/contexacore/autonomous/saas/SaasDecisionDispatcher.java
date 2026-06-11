/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.autonomous.saas.client.SaasDecisionHttpClient;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import jakarta.persistence.OptimisticLockException;
import org.springframework.data.domain.PageRequest;
import org.springframework.dao.OptimisticLockingFailureException;
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
        if (outboxId == null) {
            return;
        }
        if (!claim(outboxId, LocalDateTime.now())) {
            return;
        }
        SecurityDecisionForwardingOutboxRecord record = repository.findById(outboxId).orElse(null);
        if (!isClaimed(record)) {
            return;
        }
        doDispatch(record);
    }

    public void dispatchPendingBatch() {
        int batchSize = Math.max(1, properties.getOutboxBatchSize());
        List<Long> outboxIds = repository.findDispatchableIds(
                DISPATCHABLE_STATUSES,
                LocalDateTime.now(),
                PageRequest.of(0, batchSize));
        for (Long outboxId : outboxIds) {
            dispatch(outboxId);
        }
    }

    private boolean claim(Long outboxId, LocalDateTime now) {
        int claimed = repository.claimForDispatch(
                outboxId,
                DISPATCHABLE_STATUSES,
                SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING,
                now);
        return claimed == 1;
    }

    private void doDispatch(SecurityDecisionForwardingOutboxRecord record) {
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
        saveFinalState(record);
    }

    private boolean isClaimed(SecurityDecisionForwardingOutboxRecord record) {
        return record != null && SecurityDecisionForwardingOutboxRecord.STATUS_DISPATCHING.equals(record.getStatus());
    }

    private void saveFinalState(SecurityDecisionForwardingOutboxRecord record) {
        try {
            repository.saveAndFlush(record);
        }
        catch (OptimisticLockException | OptimisticLockingFailureException ex) {
            // The row was deleted or superseded after this worker claimed it. Do not leak scheduler noise to callers.
        }
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
