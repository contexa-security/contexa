package io.contexa.contexacore.autonomous.execution;

import io.contexa.contexacore.autonomous.exception.DelegatedExecutionContext;
import io.contexa.contexacore.autonomous.exception.DelegatedExecutionLineageSummary;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DelegatedExecutionLineageSummaryTest {

    @Test
    void declaredDelegatedExecutionProducesBoundFacts() {
        DelegatedExecutionContext context = new DelegatedExecutionContext(
                "exec-001",
                DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT,
                DelegatedExecutionContext.LINEAGE_STATE_DECLARED,
                "user-1",
                "agent-1",
                "runtime-1",
                "delegation-1",
                null,
                "CONTAIN_INCIDENT",
                "INCIDENT_RESPONSE",
                List.of("scope.read"),
                List.of("scope.read"),
                List.of("search", "block"),
                "permit-1",
                "approval-1",
                LocalDateTime.of(2026, 3, 18, 9, 0),
                LocalDateTime.of(2026, 3, 18, 9, 30));

        DelegatedExecutionLineageSummary summary = DelegatedExecutionLineageSummary.from(context);

        assertThat(summary.delegatedExecution()).isTrue();
        assertThat(summary.declaredLineage()).isTrue();
        assertThat(summary.scopeBound()).isTrue();
        assertThat(summary.permitBound()).isTrue();
        assertThat(summary.approvalBound()).isTrue();
        assertThat(summary.timeBound()).isTrue();
        assertThat(summary.toolChainDepth()).isEqualTo(2);
        assertThat(summary.facts()).contains("DECLARED_LINEAGE", "PERMIT_BOUND", "APPROVAL_BOUND", "TOOL_CHAIN_DECLARED");
    }

    @Test
    void imputedExecutionWithoutPurposeSignalsReviewFacts() {
        DelegatedExecutionContext context = DelegatedExecutionContext.imputedServiceClient(null, "tenant-runtime", List.of());

        DelegatedExecutionLineageSummary summary = DelegatedExecutionLineageSummary.from(context);

        assertThat(summary.delegatedExecution()).isTrue();
        assertThat(summary.declaredLineage()).isFalse();
        assertThat(summary.facts()).contains("IMPUTED_SERVICE_CLIENT_LINEAGE", "UNSCOPED_EXECUTION", "PURPOSE_BOUND", "ACTOR_USER_IMPUTED");
    }
}