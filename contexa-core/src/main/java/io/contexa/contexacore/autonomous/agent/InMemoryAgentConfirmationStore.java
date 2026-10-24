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
package io.contexa.contexacore.autonomous.agent;

import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** The confirmations kept in memory, the newest {@link #CAPACITY}; a restart forgets them. */
public class InMemoryAgentConfirmationStore implements AgentConfirmationStore {

    static final int CAPACITY = 10_000;

    private final Map<String, AgentConfirmation> confirmations = new LinkedHashMap<>();

    @Override
    public synchronized AgentConfirmation save(AgentConfirmation confirmation) {
        confirmations.remove(confirmation.confirmationId());
        confirmations.put(confirmation.confirmationId(), confirmation);
        while (confirmations.size() > CAPACITY) {
            confirmations.remove(confirmations.keySet().iterator().next());
        }
        return confirmation;
    }

    @Override
    public synchronized Optional<AgentConfirmation> find(String confirmationId) {
        return Optional.ofNullable(confirmationId != null ? confirmations.get(confirmationId) : null);
    }

    @Override
    public synchronized Optional<AgentConfirmation> latest(String subjectKey, String requestHash,
                                                           AgentConfirmation.Status status) {
        return confirmations.values().stream()
                .filter(confirmation -> confirmation.status() == status
                        && confirmation.subjectKey().equals(subjectKey)
                        && confirmation.requestHash().equals(requestHash))
                .max(Comparator.comparing(AgentConfirmation::createdAt));
    }

    @Override
    public synchronized boolean transition(AgentConfirmation next, AgentConfirmation.Status expected) {
        AgentConfirmation current = confirmations.get(next.confirmationId());
        if (current == null || current.status() != expected) {
            return false;
        }
        confirmations.put(next.confirmationId(), next);
        return true;
    }

    @Override
    public synchronized boolean markUsed(String confirmationId, String requestHash, Instant usedAt) {
        AgentConfirmation current = confirmations.get(confirmationId);
        if (current == null || current.status() != AgentConfirmation.Status.APPROVED
                || !current.requestHash().equals(requestHash)) {
            return false;
        }
        confirmations.put(confirmationId, current.withStatus(AgentConfirmation.Status.USED, usedAt));
        return true;
    }

    @Override
    public synchronized List<AgentConfirmation> forRecipient(String recipientId, int limit) {
        return confirmations.values().stream()
                .filter(confirmation -> confirmation.recipientId().equals(recipientId))
                .sorted(Comparator.comparing(AgentConfirmation::createdAt).reversed())
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public synchronized List<AgentConfirmation> overdue(Instant now, int limit) {
        return confirmations.values().stream()
                .filter(confirmation -> (confirmation.status() == AgentConfirmation.Status.PENDING
                        || confirmation.status() == AgentConfirmation.Status.APPROVED)
                        && !confirmation.expiresAt().isAfter(now))
                .sorted(Comparator.comparing(AgentConfirmation::expiresAt))
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public synchronized void removeForUser(String userId) {
        if (userId != null) {
            confirmations.values().removeIf(confirmation -> confirmation.userId().equals(userId)
                    || confirmation.recipientId().equals(userId));
        }
    }

    @Override
    public synchronized List<AgentConfirmation> list(@Nullable String tenantId, int limit) {
        return confirmations.values().stream()
                .filter(confirmation -> tenantId == null || Objects.equals(tenantId, confirmation.tenantId()))
                .sorted(Comparator.comparing(AgentConfirmation::createdAt).reversed())
                .limit(Math.max(0, limit))
                .toList();
    }
}
