package io.contexa.contexacommon.approval;

import io.contexa.contexacommon.mcp.approval.AiNativeActionApprovalCategory;
import io.contexa.contexacommon.mcp.approval.AiNativeActionApprovalClassifier;
import io.contexa.contexacommon.mcp.approval.AiNativeExecutionContinuityFingerprint;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AiNativeActionApprovalClassifierTest {

    @Test
    void classifyReturnsPrivilegedExportWhenExportSignalsExist() {
        AiNativeActionApprovalCategory category = AiNativeActionApprovalClassifier.classify(
                "tenant_export",
                "mcp.tool.tenant_export.execute",
                "MUTATING",
                List.of("BULK_EXPORT"),
                "export all tenant records to csv");

        assertThat(category).isEqualTo(AiNativeActionApprovalCategory.PRIVILEGED_EXPORT);
    }

    @Test
    void classifyReturnsConnectorReconfigurationWhenConnectorSignalsExist() {
        AiNativeActionApprovalCategory category = AiNativeActionApprovalClassifier.classify(
                "connector_update",
                "mcp.tool.connector_update.execute",
                "MUTATING",
                List.of(),
                "rotate webhook credential and reconfigure connector endpoint");

        assertThat(category).isEqualTo(AiNativeActionApprovalCategory.CONNECTOR_RECONFIGURATION);
    }

    @Test
    void fingerprintReturnsStableDigestForSameInputs() {
        String first = AiNativeExecutionContinuityFingerprint.fingerprint(
                "tenant-a",
                "user-1",
                "AGENT",
                "DELEGATED_AGENT",
                "req-1",
                "exec-1",
                "deleg-1",
                "incident containment",
                List.of("scope.write", "scope.read"),
                AiNativeActionApprovalCategory.DESTRUCTIVE_TOOL.name());
        String second = AiNativeExecutionContinuityFingerprint.fingerprint(
                "tenant-a",
                "user-1",
                "AGENT",
                "DELEGATED_AGENT",
                "req-1",
                "exec-1",
                "deleg-1",
                "incident containment",
                List.of("scope.read", "scope.write"),
                AiNativeActionApprovalCategory.DESTRUCTIVE_TOOL.name());

        assertThat(first).isEqualTo(second);
    }
}