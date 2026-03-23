package io.contexa.contexacore.autonomous.execution;

import io.contexa.contexacore.autonomous.exception.*;
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