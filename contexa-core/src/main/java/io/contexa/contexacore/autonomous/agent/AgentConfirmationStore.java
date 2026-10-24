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
import java.util.List;
import java.util.Optional;

/**
 * Where the confirmations of agents' requests are kept (docs/agent A5-2). A decision and the use of an approval are
 * each made once: {@link #transition} and {@link #markUsed} change a confirmation only from the status they expect.
 * Contexa keeps them in memory by default and in its database with the console.
 */
public interface AgentConfirmationStore {

    AgentConfirmation save(AgentConfirmation confirmation);

    Optional<AgentConfirmation> find(String confirmationId);

    /**
     * The latest confirmation of the subject's request in the status, or empty.
     *
     * @param subjectKey the key the subject's decisions are kept under ({@link AgentConfirmation#subjectKey()})
     */
    Optional<AgentConfirmation> latest(String subjectKey, String requestHash, AgentConfirmation.Status status);

    /**
     * Replaces the confirmation with its next state when it still stands in the expected status.
     *
     * @return whether it was replaced; false when another decision came first
     */
    boolean transition(AgentConfirmation next, AgentConfirmation.Status expected);

    /**
     * Marks the approval used by the request it is bound to.
     *
     * @return whether it was the approval's one use
     */
    boolean markUsed(String confirmationId, String requestHash, Instant usedAt);

    /** The person's confirmations, latest first. */
    List<AgentConfirmation> forRecipient(String recipientId, int limit);

    /** The confirmations still waiting, or approved and not used, whose time ran out by {@code now}. */
    List<AgentConfirmation> overdue(Instant now, int limit);

    /** Every confirmation of the tenant (every tenant's for {@code null}), latest first. */
    List<AgentConfirmation> list(@Nullable String tenantId, int limit);

    /** Forgets the confirmations of the user's requests and the ones the user was to decide (account deleted). */
    void removeForUser(String userId);
}
