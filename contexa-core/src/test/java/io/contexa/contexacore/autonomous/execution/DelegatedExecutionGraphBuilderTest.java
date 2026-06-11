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

class DelegatedExecutionGraphBuilderTest {

    private final DelegatedExecutionGraphBuilder builder = new DelegatedExecutionGraphBuilder(new DelegatedExecutionFingerprintService());

    @Test
    void buildProducesStableFingerprintsAndPolicyContext() {
        DelegatedExecutionContext context = new DelegatedExecutionContext(
                "exec-graph-1",
                DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT,
                DelegatedExecutionContext.LINEAGE_STATE_DECLARED,
                "user-1",
                "agent-1",
                "runtime-1",
                "delegation-1",
                "parent-1",
                "SUMMARIZE_INCIDENT",
                "INCIDENT_RESPONSE",
                List.of("scope.read", "scope.write"),
                List.of("scope.read"),
                List.of("search", "summarize"),
                "permit-1",
                "approval-1",
                LocalDateTime.of(2026, 3, 18, 9, 0),
                LocalDateTime.of(2026, 3, 18, 9, 30));

        DelegatedExecutionGraph graph = builder.build(
                "tenant-acme",
                "tenant-acme-runtime",
                true,
                context,
                "xai-decision-ingest",
                "INGEST",
                "/api/saas/runtime/xai/decision-ingestions",
                "POST",
                "xai:decision:corr-001",
                LocalDateTime.of(2026, 3, 18, 9, 5));

        assertThat(graph.executionKey()).isEqualTo("exec-graph-1");
        assertThat(graph.executionFingerprint()).hasSize(64);
        assertThat(graph.requestFingerprint()).hasSize(64);

        DelegatedExecutionPolicyContext policyContext = DelegatedExecutionPolicyContext.from(graph);
        assertThat(policyContext.delegatedExecution()).isTrue();
        assertThat(policyContext.scopeBound()).isTrue();
        assertThat(policyContext.permitBound()).isTrue();
        assertThat(policyContext.approvalBound()).isTrue();
        assertThat(policyContext.lineageSummary().facts()).contains("DECLARED_LINEAGE", "PURPOSE_BOUND", "APPROVED_SCOPE_BOUND");
    }
}
