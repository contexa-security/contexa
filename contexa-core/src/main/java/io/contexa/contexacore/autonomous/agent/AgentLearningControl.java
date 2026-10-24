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

import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.support.PastRecordQuery;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.function.Supplier;

/**
 * An operator's control of what an agent learned (docs/agent A3-8, AG-11j): the learning of an agent, or of one of its
 * delegations, is quarantined (kept but never read, and nothing more is learned while it lasts), released, or removed.
 * An agent's learning is its stored baselines and work-profile observations under its learning keys (A3-1) and its
 * decision records; a delegation's is its decision records only. An agent's baseline and work profile are kept per
 * agent, not per delegation, and are read and learned before a request's delegation record is looked up, so only the
 * agent's quarantine stops them. The learning of other agents and of people is never touched.
 */
public class AgentLearningControl {

    /** What was done and to how many stored items. */
    public record Outcome(String action, String agentId, @Nullable String delegationId, int records, int baselines,
                          int observations) {
    }

    public static final String QUARANTINE = "QUARANTINE";
    public static final String RELEASE = "RELEASE";
    public static final String REMOVE = "REMOVE";

    private static final String AGENT_SCOPE = "agent:";
    private static final String DELEGATION_SCOPE = "delegation:";

    private final SecurityContextDataStore contextStore;
    private final BaselineDataStore baselineStore;
    private final Supplier<PastRecordQuery> records;

    public AgentLearningControl(@Nullable SecurityContextDataStore contextStore, @Nullable BaselineDataStore baselineStore,
                                Supplier<PastRecordQuery> records) {
        this.contextStore = contextStore;
        this.baselineStore = baselineStore;
        this.records = records != null ? records : PastRecordQuery::unavailable;
    }

    /** Quarantines the learning of the agent, or of its delegation when one is given. */
    public Outcome quarantine(String agentId, @Nullable String delegationId) {
        String agent = required(agentId);
        String delegation = text(delegationId);
        store().setLearningQuarantined(scope(agent, delegation), true);
        int changed = query().quarantineAgentRecords(agent, delegation);
        return new Outcome(QUARANTINE, agent, delegation, changed, 0, 0);
    }

    /**
     * Releases a quarantine: the records get back the learning state they had, and learning goes on. A quarantine that
     * still holds stays: releasing the agent keeps the records of its delegations still quarantined, and releasing a
     * delegation of an agent still quarantined changes no record.
     */
    public Outcome release(String agentId, @Nullable String delegationId) {
        String agent = required(agentId);
        String delegation = text(delegationId);
        SecurityContextDataStore store = store();
        store.setLearningQuarantined(scope(agent, delegation), false);
        if (delegation != null && store.learningQuarantined(scope(agent, null))) {
            return new Outcome(RELEASE, agent, delegation, 0, 0, 0);
        }
        List<String> quarantinedDelegations = delegation != null ? List.of()
                : store.learningQuarantineScopes().stream()
                .filter(scope -> scope.startsWith(DELEGATION_SCOPE))
                .map(scope -> scope.substring(DELEGATION_SCOPE.length()))
                .toList();
        int changed = query().releaseAgentRecords(agent, delegation, quarantinedDelegations);
        return new Outcome(RELEASE, agent, delegation, changed, 0, 0);
    }

    /**
     * Removes the learning: the decision records of the agent (or of its delegation), and for an agent its stored
     * baselines and work-profile observations under every learning key. A quarantine in force stays.
     */
    public Outcome remove(String agentId, @Nullable String delegationId) {
        String agent = required(agentId);
        int removedRecords = query().removeAgentRecords(agent, text(delegationId));
        if (text(delegationId) != null) {
            return new Outcome(REMOVE, agent, text(delegationId), removedRecords, 0, 0);
        }
        int baselines = baselineStore != null ? baselineStore.deleteAgentBaselines(agent) : 0;
        int observations = store().deleteAgentLearning(agent);
        return new Outcome(REMOVE, agent, null, removedRecords, baselines, observations);
    }

    /** Whether the learning of the agent, or of the delegation, is quarantined. */
    public boolean quarantined(String agentId, @Nullable String delegationId) {
        return StringUtils.hasText(agentId) && contextStore != null
                && contextStore.learningQuarantined(scope(agentId.trim(), delegationId));
    }

    /**
     * Whether an operator quarantined the agent the subject is: its baseline and work profile are then neither read nor
     * learned. A person's learning is never quarantined here.
     */
    public static boolean learningQuarantined(@Nullable SecurityContextDataStore store,
                                              @Nullable LearningSubject subject) {
        if (store == null || subject == null || !subject.agent()) {
            return false;
        }
        return store.learningQuarantined(scope(subject.agentId(), null));
    }

    /**
     * Whether the decision record of the subject's request is stored quarantined: its agent, or the delegation it runs
     * under, is quarantined.
     */
    public static boolean recordsQuarantined(@Nullable SecurityContextDataStore store,
                                             @Nullable LearningSubject subject) {
        if (learningQuarantined(store, subject)) {
            return true;
        }
        return store != null && subject != null && subject.agent() && subject.delegationId() != null
                && store.learningQuarantined(scope(subject.agentId(), subject.delegationId()));
    }

    private static String scope(String agentId, @Nullable String delegationId) {
        return text(delegationId) != null ? DELEGATION_SCOPE + delegationId.trim() : AGENT_SCOPE + agentId;
    }

    private SecurityContextDataStore store() {
        if (contextStore == null) {
            throw new IllegalStateException("No security context data store keeps the learning quarantine");
        }
        return contextStore;
    }

    private PastRecordQuery query() {
        PastRecordQuery query = records.get();
        return query != null ? query : PastRecordQuery.unavailable();
    }

    private static String required(String agentId) {
        String agent = text(agentId);
        if (agent == null) {
            throw new IllegalArgumentException("An agent id is required");
        }
        return agent;
    }

    @Nullable
    private static String text(@Nullable String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
