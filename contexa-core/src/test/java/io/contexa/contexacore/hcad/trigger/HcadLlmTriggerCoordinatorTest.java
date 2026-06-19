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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.hcad.trigger.store.InMemoryAnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HcadLlmTriggerCoordinatorTest {

    private static final String ACTOR_SESSION_KEY = PendingAnomalyKeyFactory.buildBaseKey("alice", "ctx-1");

    @Test
    @DisplayName("same trusted anchor should allow at most one LLM trigger across different paths")
    void tryAcquire_sameAnchorDifferentPaths_shouldSuppressSecondTrigger() {
        HcadLlmTriggerCoordinator coordinator = coordinator();
        PendingAnomalyEvidenceReport first = triggerReport(
                "/api/orders/1001",
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"));
        PendingAnomalyEvidenceReport second = triggerReport(
                "/api/orders/1002",
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"));

        HcadLlmTriggerCoordinator.TriggerLease firstLease = coordinator.tryAcquire(first, ACTOR_SESSION_KEY);
        coordinator.markCooldown(firstLease);
        HcadLlmTriggerCoordinator.TriggerLease secondLease = coordinator.tryAcquire(second, ACTOR_SESSION_KEY);

        assertThat(firstLease.acquired()).isTrue();
        assertThat(secondLease.acquired()).isFalse();
        assertThat(secondLease.duplicateSuppressed()).isTrue();
        assertThat(secondLease.dedupKey()).isEqualTo(firstLease.dedupKey());
        assertThat(secondLease.escalationKey()).isEqualTo(firstLease.escalationKey());
    }

    @Test
    @DisplayName("new trusted anchor should be allowed as a separate escalation evaluation")
    void tryAcquire_newTrustedAnchor_shouldAcquireSeparateEscalation() {
        HcadLlmTriggerCoordinator coordinator = coordinator();
        PendingAnomalyEvidenceReport impossibleTravel = triggerReport(
                "/api/orders",
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"));
        PendingAnomalyEvidenceReport failedLoginBurst = triggerReport(
                "/api/orders",
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"));

        HcadLlmTriggerCoordinator.TriggerLease firstLease = coordinator.tryAcquire(impossibleTravel, ACTOR_SESSION_KEY);
        coordinator.markCooldown(firstLease);
        HcadLlmTriggerCoordinator.TriggerLease secondLease = coordinator.tryAcquire(failedLoginBurst, ACTOR_SESSION_KEY);

        assertThat(firstLease.acquired()).isTrue();
        assertThat(secondLease.acquired()).isTrue();
        assertThat(secondLease.dedupKey()).isNotEqualTo(firstLease.dedupKey());
        assertThat(secondLease.escalationKey()).isNotEqualTo(firstLease.escalationKey());
    }

    @Test
    @DisplayName("corroborating-only path changes should not produce an escalation key")
    void resolveEscalationKey_withoutTrustedAnchor_shouldReturnNull() {
        HcadLlmTriggerCoordinator coordinator = coordinator();
        PendingAnomalyEvidenceReport pathOnly = triggerReport(
                "/api/orders/1001",
                List.of(),
                List.of("PREVIOUS_PATH_JUMP", "REQUEST_BURST"));

        assertThat(coordinator.resolveEscalationKey(pathOnly)).isNull();
    }

    private HcadLlmTriggerCoordinator coordinator() {
        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().getLlmRateLimit().setEnabled(false);
        return new HcadLlmTriggerCoordinator(new InMemoryAnalysisTriggerStateRepository(), properties);
    }

    private PendingAnomalyEvidenceReport triggerReport(
            String path,
            List<String> anchors,
            List<String> corroborating) {
        String riskSignature = PendingAnomalyKeyFactory.buildTrustedSignalSignature(anchors, corroborating);
        String triggerStateKey = PendingAnomalyKeyFactory.buildActorSessionDedupKey(ACTOR_SESSION_KEY, riskSignature);
        List<String> reasons = new ArrayList<>(anchors);
        for (String signal : corroborating) {
            if (!reasons.contains(signal)) {
                reasons.add(signal);
            }
        }
        return new PendingAnomalyEvidenceReport(
                true,
                "alice",
                "ctx-1",
                triggerStateKey,
                "request-1",
                "session-1",
                path,
                "GET",
                "203.0.113.10",
                75,
                "REDLINE",
                true,
                "hcad-promotion-v2-trusted-projection",
                anchors,
                corroborating,
                reasons,
                "trusted HCAD trigger",
                riskSignature,
                Map.of("actorSessionKey", ACTOR_SESSION_KEY));
    }
}
