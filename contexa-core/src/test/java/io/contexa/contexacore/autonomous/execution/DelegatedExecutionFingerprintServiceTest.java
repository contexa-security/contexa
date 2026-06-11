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
package io.contexa.contexacore.autonomous.execution;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DelegatedExecutionFingerprintServiceTest {

    private final DelegatedExecutionFingerprintService service = new DelegatedExecutionFingerprintService();

    @Test
    void computeRequestFingerprintNormalizesMethodPathAndResourceFingerprint() {
        String left = service.computeRequestFingerprint("POST", " /api/saas/runtime/xai/decision-ingestions ", "XAI:DECISION:CORR-001");
        String right = service.computeRequestFingerprint("post", "/api/saas/runtime/xai/decision-ingestions", "xai:decision:corr-001");

        assertThat(left).isEqualTo(right);
        assertThat(left).hasSize(64);
    }

    @Test
    void resolveExecutionKeyPrefersDeclaredExecutionId() {
        DelegatedExecutionContext context = new DelegatedExecutionContext(
                "exec-001",
                DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT,
                DelegatedExecutionContext.LINEAGE_STATE_DECLARED,
                "user-1",
                "agent-1",
                "runtime-1",
                "delegation-1",
                "parent-1",
                "SUMMARIZE_INCIDENT",
                "INCIDENT_RESPONSE",
                List.of("scope.read"),
                List.of("scope.read"),
                List.of("search", "summarize"),
                "permit-1",
                "approval-1",
                LocalDateTime.of(2026, 3, 18, 9, 0),
                LocalDateTime.of(2026, 3, 18, 9, 30));

        String key = service.resolveExecutionKey(
                "tenant-acme",
                "tenant-acme-runtime",
                context,
                "xai-decision-ingest",
                "INGEST",
                "xai:decision:corr-001",
                "request-fingerprint-1");

        assertThat(key).isEqualTo("exec-001");
    }

    @Test
    void computeExecutionFingerprintChangesWhenDelegationContextChanges() {
        DelegatedExecutionContext declared = new DelegatedExecutionContext(
                null,
                DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT,
                DelegatedExecutionContext.LINEAGE_STATE_DECLARED,
                "user-1",
                "agent-1",
                "runtime-1",
                "delegation-1",
                null,
                "SUMMARIZE_INCIDENT",
                "INCIDENT_RESPONSE",
                List.of("scope.read"),
                List.of("scope.read"),
                List.of("search"),
                "permit-1",
                null,
                null,
                null);
        DelegatedExecutionContext imputed = DelegatedExecutionContext.imputedServiceClient("user-1", "tenant-acme-runtime", List.of("scope.read"));

        String declaredFingerprint = service.computeExecutionFingerprint(
                "tenant-acme",
                "tenant-acme-runtime",
                declared,
                "xai-decision-ingest",
                "INGEST",
                "xai:decision:corr-001",
                "request-fingerprint-1");
        String imputedFingerprint = service.computeExecutionFingerprint(
                "tenant-acme",
                "tenant-acme-runtime",
                imputed,
                "xai-decision-ingest",
                "INGEST",
                "xai:decision:corr-001",
                "request-fingerprint-1");

        assertThat(declaredFingerprint).isNotEqualTo(imputedFingerprint);
    }
}
