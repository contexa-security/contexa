package io.contexa.contexacore.verification.runtime.request;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationCcrCheckEvaluatorTest {

    private final OfficialVerificationCcrCheckEvaluator evaluator = new OfficialVerificationCcrCheckEvaluator();

    @Test
    void preservesAllTwelvePassingCcrChecksForCompleteContextEvidence() {
        OfficialVerificationCcrExecutionService.EndpointDefinition endpoint =
                new OfficialVerificationCcrExecutionService.EndpointDefinition(
                        "normal", "Normal Resource", "/verification/runtime/probe/normal/resource-1", "resource-1"
                );
        Map<String, Object> eventMetadata = Map.of(
                "authMethod", "PASSWORD",
                "authorizationEffect", "ALLOW",
                "resourceSensitivity", "STANDARD",
                "isSensitiveResource", false,
                "effectiveRoles", List.of("ADMIN"),
                "effectivePermissions", List.of("READ")
        );
        Map<String, Object> sessionMetadata = Map.of(
                "userId", "verification-user",
                "authMethod", "PASSWORD",
                "requestCount", 1
        );
        Map<String, Object> behaviorMetadata = Map.of(
                "currentUserAgentOS", "Windows 11",
                "currentUserAgentBrowser", "Chrome 120"
        );

        List<OfficialVerificationCcrExecutionService.CcrCheckResult> checks = evaluator.evaluate(
                endpoint,
                eventMetadata,
                sessionMetadata,
                behaviorMetadata,
                Map.of("promptKey", "official-ccr")
        );

        assertThat(checks).hasSize(12).allMatch(OfficialVerificationCcrExecutionService.CcrCheckResult::pass);
        assertThat(checks).extracting(OfficialVerificationCcrExecutionService.CcrCheckResult::source)
                .containsExactly(
                        "event.metadata.authMethod",
                        "event.metadata.authorizationEffect",
                        "event.metadata.resourceSensitivity",
                        "event.metadata.isSensitiveResource",
                        "event.metadata.effectiveRoles",
                        "event.metadata.effectivePermissions",
                        "sessionCtx.userId",
                        "sessionCtx.authMethod",
                        "sessionCtx.requestCount",
                        "behaviorCtx.currentUserAgentOS",
                        "behaviorCtx.currentUserAgentBrowser",
                        "promptExecutionMetadata"
                );
    }
}