package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationRapEvidenceFactoryTest {

    @Test
    void fullyAllowedContextLedgerKeepsAllExistingRapChecksPassing() {
        OfficialVerificationRapEvidenceFactory factory = new OfficialVerificationRapEvidenceFactory();
        Map<String, Object> promptPayload = Map.of(
                "correlationId", "request-1",
                "requestedDocumentCount", 2,
                "allowedDocumentCount", 2,
                "deniedDocumentCount", 0,
                "retrievalPurpose", "official-verification",
                "deniedReasons", List.of(),
                "contexts", List.of(
                        Map.of("includedInPrompt", true, "authorizationDecision", "ALLOWED_ROLE"),
                        Map.of("includedInPrompt", true, "authorizationDecision", "ALLOWED_POLICY")));
        PromptContextAuditForwardingOutboxRecord promptOutbox = PromptContextAuditForwardingOutboxRecord.builder()
                .auditId("audit-1")
                .correlationId("request-1")
                .build();
        var authorization = factory.summarizeAuthorization(promptPayload);

        var checks = factory.buildChecks(
                "request-1",
                Map.of("requestId", "request-1"),
                Map.of("requestId", "request-1"),
                promptPayload,
                promptOutbox,
                authorization);

        assertThat(checks).hasSize(13).allMatch(OfficialVerificationRapExecutionService.RapCheckResult::pass);
        assertThat(authorization.authorizationPrecision()).isEqualTo(100.0d);
    }
}