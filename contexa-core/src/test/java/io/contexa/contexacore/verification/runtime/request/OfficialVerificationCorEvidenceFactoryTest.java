package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationCorEvidenceFactoryTest {

    @Test
    void sameUserAndPurposeContextKeepsAllExistingCorChecksPassing() {
        OfficialVerificationCorEvidenceFactory factory = new OfficialVerificationCorEvidenceFactory();
        Map<String, Object> promptPayload = Map.of(
                "correlationId", "request-1",
                "requestedDocumentCount", 1,
                "allowedDocumentCount", 1,
                "deniedDocumentCount", 0,
                "retrievalPurpose", "official-verification",
                "deniedReasons", List.of(),
                "contexts", List.of(Map.of(
                        "userId", "user-1",
                        "retrievalPurpose", "official-verification",
                        "purposeMatch", true,
                        "authorizationDecision", "ALLOWED_POLICY",
                        "includedInPrompt", true)));
        PromptContextAuditForwardingOutboxRecord promptOutbox = PromptContextAuditForwardingOutboxRecord.builder()
                .auditId("audit-1")
                .correlationId("request-1")
                .build();
        var contamination = factory.summarizeContamination("user-1", promptPayload);

        var checks = factory.buildChecks(
                "request-1",
                Map.of("requestId", "request-1"),
                Map.of("requestId", "request-1"),
                promptPayload,
                promptOutbox,
                contamination);

        assertThat(checks).hasSize(13).allMatch(OfficialVerificationCorExecutionService.CorCheckResult::pass);
        assertThat(contamination.contaminationRate()).isZero();
    }
}