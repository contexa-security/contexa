package io.contexa.contexacore.verification.runtime.request;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationCcsrCheckEvaluatorTest {

    @Test
    void preservesAllSixRequestToPromptConsistencyChecks() {
        String requestPath = "/verification/runtime/probe/normal/resource-1";
        Map<String, Object> eventMetadata = Map.of(
                "requestPath", requestPath,
                "clientIp", "198.51.100.24",
                "mfaVerified", true,
                "resourceSensitivity", "STANDARD",
                "authorizationEffect", "ALLOW",
                "demoPhase", "INITIAL"
        );
        Map<String, Object> promptPayload = Map.of(
                "userPrompt",
                "RequestPath: " + requestPath
                        + " ClientIp: 198.51.100.24 MfaVerified: true"
                        + " Sensitivity: STANDARD AuthorizationEffect: ALLOW"
        );
        OfficialVerificationCcsrExecutionService.EndpointDefinition endpoint =
                new OfficialVerificationCcsrExecutionService.EndpointDefinition(
                        "normal", "Normal Resource", requestPath, "resource-1"
                );

        List<OfficialVerificationCcsrExecutionService.CcsrCheckResult> checks =
                new OfficialVerificationCcsrCheckEvaluator().evaluate(
                        endpoint, Map.of("demoPhase", "INITIAL"), eventMetadata, promptPayload
                );

        assertThat(checks).hasSize(6).allMatch(OfficialVerificationCcsrExecutionService.CcsrCheckResult::pass);
    }
}