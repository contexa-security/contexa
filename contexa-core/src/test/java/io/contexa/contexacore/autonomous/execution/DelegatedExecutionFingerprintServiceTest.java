package io.contexa.contexacore.autonomous.execution;

import io.contexa.contexacore.autonomous.exception.DelegatedExecutionContext;
import io.contexa.contexacore.autonomous.exception.DelegatedExecutionFingerprintService;
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
