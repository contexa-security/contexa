/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An ERROR line says something failed: an application's monitoring wakes somebody for it. What Contexa does in its ordinary
 * work stays out of that level. A lookup, a success or a skipped duplicate is DEBUG or INFO; a decision and its safe-side
 * outcome (a denial, a block, a wrong code, an expired token, a model answer that was replaced) is WARN. Reads the sources,
 * like the other guards, because most of these lines sit behind a whole decision flow.
 */
class OrdinaryFlowLogLevelContractTest {

    private static final Map<String, List<String>> DEBUG = new LinkedHashMap<>();
    private static final Map<String, List<String>> INFO = new LinkedHashMap<>();
    private static final Map<String, List<String>> WARN = new LinkedHashMap<>();

    static {
        DEBUG.put("UserManagementServiceImpl.java", List.of(
                "[UserManagementService.modifyUser] findByIdWithGroupsRolesAndPermissions",
                "[UserManagementService.findUser] findByIdWithGroupsRolesAndPermissions"));
        DEBUG.put("AccessCenterService.java", List.of("[AccessCenterController] findByIdWithGroupsRolesAndPermissions"));
        DEBUG.put("DefaultMfaPolicyEvaluator.java", List.of("[DefaultMfaPolicyEvaluator] findByUsernameWithGroupsRolesAndPermissions"));
        DEBUG.put("SecurityPlaneAgent.java", List.of("Agent {} is already running", "[SecurityPlaneAgent] Event {} already processed"));
        DEBUG.put("SoarContextProviderImpl.java", List.of(
                "Created SOAR context from {} events", "Updated context severity to", "Updated context execution mode to",
                "Enriched SOAR context with", "Created default SOAR context", "Creating emergency SOAR context",
                "Created SOAR context from {} threat indicators"));
        DEBUG.put("Layer2ExpertStrategy.java", List.of("[Layer2] Session context cache miss", "[Layer2] Behavior analysis cache miss"));
        DEBUG.put("DefaultStreamingHandler.java", List.of("Tools not enabled.", "No tool configuration found."));
        DEBUG.put("LoginPolicyService.java", List.of("[login-policy] success reset skipped"));
        DEBUG.put("AbstractMfaPolicyEvaluator.java", List.of("User preferred factor {} not available"));
        DEBUG.put("ResourceRegistryServiceImpl.java", List.of(
                "Empty batch, skipping processing", "No valid resources, skipping AI suggestion", "AI did not return suggestion for resource"));
        DEBUG.put("AutoConditionTemplateService.java", List.of("Unique name generation required timestamp fallback"));
        DEBUG.put("InMemoryZeroTrustActionRepository.java", List.of("[InMemoryZTARepository] Context binding hash mismatch detected"));
        DEBUG.put("ZeroTrustActionRedisRepository.java", List.of(
                "[ZeroTrustActionRedisRepository] Context binding hash mismatch detected",
                "[ZeroTrustActionRedisRepository] Last verified context binding hash mismatch"));

        INFO.put("NoOpSecurityActionEventPublisher.java", List.of("[NoOpActionPublisher] SOAR auto-response is disabled"));
        INFO.put("AuditLogRetentionScheduler.java", List.of("Audit log retention: deleted"));
        INFO.put("ResourceRegistryServiceImpl.java", List.of(
                "{} resources not found in current code", "Resource status reverted to PERMISSION_CREATED"));
        INFO.put("IdentityOAuth2AutoConfiguration.java", List.of("[OAuth2] Issuer URI not configured"));

        WARN.put("IpAccessFilter.java", List.of("IP access denied for", "IP access rejected by allow-list"));
        WARN.put("BlockedUserService.java", List.of("[BlockedUserService] MFA failed - auto response triggered"));
        WARN.put("BlockedUserTimeoutScheduler.java", List.of("Blocked user timeout - auto response triggered"));
        WARN.put("ZeroTrustAccessControlFilter.java", List.of(
                "[ZeroTrustAccessControlFilter] BLOCK MFA attempts exhausted", "[ZeroTrustAccessControlFilter] ESCALATE promoted to BLOCK"));
        WARN.put("UnifiedAuthenticationFailureHandler.java", List.of(
                "MFA Factor Failure using", "[UnifiedAuthFailure] BLOCK MFA max attempts reached", "[UnifiedAuthFailure] BLOCK MFA failed, attempt"));
        WARN.put("MfaRestAuthenticationFilter.java", List.of("Authentication failed for user"));
        WARN.put("MfaStepFilterWrapper.java", List.of(
                "Invalid context for MFA factor processing", "MFA factor processing warnings", "MFA session expired for session",
                "Retry limit exceeded for session", "State Machine rejected SUBMIT_FACTOR_CREDENTIAL event for session"));
        WARN.put("MfaFactorProcessingSuccessHandler.java", List.of("MFA Factor Processing Success using {} repository: Invalid FactorContext"));
        WARN.put("OneTimeTokenCreationSuccessHandler.java", List.of("OTT code requested while factor {} is selected", "OTT context mismatch"));
        WARN.put("MfaSignInScopeFilter.java", List.of("A login that does not meet MFA flow"));
        WARN.put("AllFactorsCompletedGuard.java", List.of("PolicyProvider returned null/invalid for user"));
        WARN.put("MfaContinuationFilter.java", List.of("Invalid MFA context for request", "MFA context warnings for request"));
        WARN.put("RetryLimitGuard.java", List.of("Factor {} retry limit exceeded", "Total retry limit exceeded"));
        WARN.put("HandleFailureAction.java", List.of("Max retry attempts exceeded"));
        WARN.put("OAuth2TokenService.java", List.of(
                "OAuth2Authorization not found for refresh token", "Refresh token is invalidated", "Refresh token is expired"));
        WARN.put("LoginPolicyService.java", List.of("[login-policy] ip blocked"));
        WARN.put("ProtectableRapidReentryGuard.java", List.of("[ProtectableRapidReentryGuard] Rapid protected re-entry denied"));
        WARN.put("CompositeLogoutHandler.java", List.of("[ForceLogout] Executing force-logout"));
        WARN.put("AISecurityContextSupport.java", List.of("[ZeroTrust] Invalidating all sessions for user"));
        WARN.put("PrimaryAuthenticationSuccessHandler.java", List.of(
                "Authentication blocked/escalated for user", "SECURITY_ALERT: Authentication blocked for user"));
        WARN.put("AIAdaptiveMfaPolicyProvider.java", List.of("AI blocked authentication for user"));
        WARN.put("SessionBasedSuccessHandler.java", List.of("Saved request ignored, it is no page to go back to"));
        WARN.put("CustomMethodSecurityExpressionRoot.java", List.of("Ownership verification failed"));
        WARN.put("ColdPathEventProcessor.java", List.of("[ColdPath] Escalate rate {}/{} ({}%) exceeded threshold"));
        WARN.put("SecurityDecisionEnforcementHandler.java", List.of("[SecurityDecisionEnforcementHandler] LLM returned no action"));
        WARN.put("AbstractTieredStrategy.java", List.of("[{}] Unknown action '{}' from LLM", "[{}] JSON parsing failed, returning default response"));
        WARN.put("ResponseParsingStep.java", List.of("[{}] Recovered truncated JSON", "[{}] Converted to Map successfully"));
        WARN.put("JsonStreamingProcessor.java", List.of("JSON repaired: original length"));
        WARN.put("ResourceRegistryServiceImpl.java", List.of(
                "AI did not return a resource naming response", "AI resource naming response contained invalid entries",
                "AI resource naming response contained identifiers that were not requested", "AI resource naming response missed"));
        WARN.put("AutoConditionTemplateService.java", List.of(
                "Specific condition template batch response is empty", "Universal condition template response is empty", "Condition template rejected"));
        WARN.put("ResourceNamingTemplate.java", List.of("ResourceNamingTemplate batch size {} exceeds"));
        WARN.put("HmacEvidenceSigner.java", List.of("[EvidenceSigning] No evidence signing key configured"));
        WARN.put("DefaultPromptQualityOfficialRunDetailService.java", List.of("[PQA-OFFICIAL-DETAIL-SLOW]"));
        WARN.put("OfficialVerificationEvidencePreflight.java", List.of("PQA sealed evidence prompt contract recovered"));
    }

    private static Map<String, Path> mainSources() throws IOException {
        Map<String, Path> sources = new LinkedHashMap<>();
        Path root = Path.of("").toAbsolutePath().getParent();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.filter(path -> path.getFileName().toString().startsWith("contexa-")).toList()) {
                Path main = module.resolve("src/main/java");
                if (Files.isDirectory(main)) {
                    try (Stream<Path> files = Files.walk(main)) {
                        files.filter(path -> path.toString().endsWith(".java")).forEach(path -> sources.put(path.getFileName().toString(), path));
                    }
                }
            }
        }
        assertThat(sources).as("the guard reads the sources of every module").hasSizeGreaterThan(1500);
        return sources;
    }

    private static Pattern logged(String level, String message) {
        return Pattern.compile("\\b(?:log|logger)\\." + level + "\\(\\s*\"" + Pattern.quote(message));
    }

    private static List<String> wrongLines(Map<String, Path> sources, String level, Map<String, List<String>> expected) throws IOException {
        List<String> wrong = new ArrayList<>();
        for (Map.Entry<String, List<String>> file : expected.entrySet()) {
            assertThat(sources).as("the source named here exists").containsKey(file.getKey());
            String text = Files.readString(sources.get(file.getKey()), StandardCharsets.UTF_8);
            for (String message : file.getValue()) {
                if (!logged(level, message).matcher(text).find() || logged("error", message).matcher(text).find()) {
                    wrong.add(file.getKey() + ": " + message);
                }
            }
        }
        return wrong;
    }

    @Test
    void tracesOfOrdinaryWorkAreDebugLines() throws IOException {
        assertThat(wrongLines(mainSources(), "debug", DEBUG)).isEmpty();
    }

    @Test
    void whatAnOperatorMayWantToSeeOfOrdinaryWorkIsAnInfoLine() throws IOException {
        assertThat(wrongLines(mainSources(), "info", INFO)).isEmpty();
    }

    @Test
    void decisionsAndSafeSideOutcomesAreWarnings() throws IOException {
        assertThat(wrongLines(mainSources(), "warn", WARN)).isEmpty();
    }
}
