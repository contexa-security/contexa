package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationMtrEvidenceFactoryTest {

    @Test
    void linkedPromptTelemetryKeepsAllExistingMtrChecksPassing() {
        OfficialVerificationMtrEvidenceFactory factory = new OfficialVerificationMtrEvidenceFactory();
        Map<String, Object> decisionMetadata = Map.of(
                "requestId", "request-1",
                "promptVersion", "v1",
                "promptHash", "prompt-hash",
                "templateKey", SecurityDecisionStandardPromptTemplate.STANDARD_TEMPLATE_KEY,
                "promptRuntimeTelemetryLinked", true);
        Map<String, Object> promptTelemetry = Map.of(
                "promptVersion", "v1",
                "promptHash", "prompt-hash",
                "systemPromptHash", "system-hash",
                "userPromptHash", "user-hash",
                "promptKey", SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE.promptKey(),
                "templateKey", SecurityDecisionStandardPromptTemplate.STANDARD_TEMPLATE_KEY);
        PromptContextAuditForwardingOutboxRecord promptOutbox = PromptContextAuditForwardingOutboxRecord.builder()
                .auditId("audit-1")
                .correlationId("request-1")
                .build();

        var checks = factory.buildChecks(
                "request-1",
                Map.of("requestId", "request-1"),
                decisionMetadata,
                promptTelemetry,
                Map.of(),
                Map.of(),
                Map.of("correlationId", "request-1"),
                null,
                promptOutbox);

        assertThat(checks).hasSize(16).allMatch(OfficialVerificationMtrExecutionService.MtrCheckResult::pass);
    }
}