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

    /**
     * Plan 2.3 B13: a dictionary prompt (v20, v21, v1.0) states MFA on its LoginMethod line and the sensitivity on its
     * ResourceClass line, each read past the line's fact id.
     */
    @Test
    void readsMfaAndSensitivityOnTheLinesOfADictionaryPrompt() {
        String requestPath = "/verification/runtime/probe/normal/resource-1";
        Map<String, Object> eventMetadata = Map.of(
                "requestPath", requestPath,
                "clientIp", "198.51.100.24",
                "mfaVerified", true,
                "resourceSensitivity", "HIGH",
                "authorizationEffect", "ALLOW",
                "demoPhase", "INITIAL"
        );
        Map<String, Object> promptPayload = Map.of("userPrompt", String.join("\n",
                "=== SESSION ===",
                "[S1] LoginMethod: PASSWORD+ONE_TIME_CODE (assurance AAL2), 2 min before this request, MFA verified",
                "=== REQUEST (time zone UTC) ===",
                "[R5] ResourceClass: SENSITIVE (sensitivity HIGH, sensitive-resource flag)",
                "[R6] Network: 198.51.100.24 (198.51.100.0/24, zone EXTERNAL)",
                "=== RECORDS AND COMPARISONS ===",
                "[F10] AuthorizationEffect: ALLOW (METHOD_AUTHORIZATION_CHECK)",
                "=== UNTRUSTED TEXT (untrusted) ===",
                "UntrustedText1: source=request path (requester); \"" + requestPath + "\""));
        OfficialVerificationCcsrExecutionService.EndpointDefinition endpoint =
                new OfficialVerificationCcsrExecutionService.EndpointDefinition(
                        "normal", "Normal Resource", requestPath, "resource-1"
                );

        List<OfficialVerificationCcsrExecutionService.CcsrCheckResult> checks =
                new OfficialVerificationCcsrCheckEvaluator().evaluate(
                        endpoint, Map.of("demoPhase", "INITIAL"), eventMetadata, promptPayload
                );

        assertThat(checks).filteredOn(check -> check.label().startsWith("mfaVerified")
                        || check.label().startsWith("resourceSensitivity"))
                .hasSize(2).allMatch(OfficialVerificationCcsrExecutionService.CcsrCheckResult::pass);
    }
}