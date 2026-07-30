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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.learning.evidence.ObservedPatternSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.RetrievedBehaviorEvidence;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityPromptContractVerifierTest {

    @Test
    @DisplayName("audit should reject stale authorization-effect missing knowledge when final effect is resolved")
    void auditShouldRejectResolvedAuthorizationEffectStillMarkedMissing() {
        String userPrompt = """
                === IDENTITY AND ROLE CONTEXT ===
                AuthorizationEffect: ALLOW
                === EXPLICIT MISSING KNOWLEDGE ===
                MissingCriticalFacts:
                - Bridge missing context: AUTHORIZATION_EFFECT.
                """;

        SecurityPromptContractAudit audit = SecurityPromptContractVerifier.audit("", userPrompt, null);

        assertThat(audit.violations())
                .contains("AUTHORIZATION_EFFECT_RESOLVED_BUT_STILL_MISSING");
    }

    @Test
    @DisplayName("audit should detect prompt-only fidelity violations for time, vocabulary, hierarchy, and provisional scope")
    void auditShouldDetectPromptOnlyFidelityViolations() {
        LearningContextEvidence learningEvidence = new LearningContextEvidence(
                new CurrentLearningContextSnapshot("10", "1", "CORPORATE", "Chrome", "Windows", "/admin/api/security-test/sensitive/*", "PASSWORD", "READ", "SENSITIVE"),
                new BaselineEvidenceSnapshot(
                        LearningEvidenceScope.PERSONAL,
                        true,
                        true,
                        20L,
                        null,
                        List.of("CORPORATE"),
                        List.of("10"),
                        List.of("1"),
                        List.of("Chrome"),
                        List.of("Windows"),
                        List.of("/admin/api/security-test/sensitive/*"),
                        List.of("PASSWORD"),
                        List.of("READ"),
                        List.of("SENSITIVE"),
                        "personal baseline established",
                        BaselineEvidenceStatus.AVAILABLE,
                        ""),
                new BaselineEvidenceSnapshot(
                        LearningEvidenceScope.SUPPORTING,
                        true,
                        false,
                        null,
                        null,
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        "",
                        BaselineEvidenceStatus.AVAILABLE,
                        ""),
                List.of(new RetrievedBehaviorEvidence(
                        LearningEvidenceScope.PERSONAL,
                        "user-1",
                        "behavior",
                        "artifact-1",
                        0.91d,
                        "10.10.0.20",
                        "CORPORATE",
                        "/admin/api/security-test/sensitive/self-sensitive-1",
                        "/admin/api/security-test/sensitive/*",
                        "10",
                        "1",
                        "Chrome",
                        "Windows",
                        "PASSWORD",
                        "READ",
                        "SENSITIVE",
                        "HIGH",
                        "FINANCE",
                        "12",
                        "false",
                        "known office request")),
                List.of(),
                new ObservedPatternSnapshot(
                        List.of("CORPORATE"),
                        List.of("10"),
                        List.of("1"),
                        List.of("Chrome"),
                        List.of("Windows"),
                        List.of("/admin/api/security-test/sensitive/*"),
                        List.of("PASSWORD"),
                        List.of("READ"),
                        List.of("SENSITIVE")),
                List.of(),
                List.of("CurrentAccessHour", "CurrentAccessHourPresentInObservedHours", "CurrentActionFamilyPresentInExpectedRoleScope"),
                List.of("ObservedHours"));

        String systemPrompt = """
                ANALYSIS ORDER
                Check CurrentAccessHourPresentInObservedHours.
                Check CurrentActionFamilyPresentInExpectedRoleScope.
                """;
        String userPrompt = """
                === CURRENT REQUEST AND EVENT ===
                User is requesting GET /admin/api/security-test/sensitive/self-sensitive-1 at 21:10.
                RequestPath: /admin/api/security-test/sensitive/self-sensitive-1
                CurrentAccessHour: 10
                AuthenticationType: UsernamePasswordAuthenticationToken
                CurrentActionFamily: READ
                CurrentResourceFamily: SENSITIVE
                BaselineProfileStatus: ESTABLISHED
                WorkProfileEvidenceState: TRUSTED
                ObservedPatternEvidenceScope: PERSONAL_BASELINE_PLUS_PERSONAL_RETRIEVED
                HistoricalComparableCount: 3
                HistoricalComparableSummary: Records=3 | Hours=10
                CurrentPathPresentInObservedPaths: UNKNOWN
                ObservedAuthenticationTypes: PASSWORD, USERNAMEPASSWORDAUTHENTICATIONTOKEN
                CurrentAccessHourPresentInObservedHours: true
                === CONTEXT COVERAGE ===
                use established supporting baseline history as limited comparison evidence only
                === ROLE AND WORK SCOPE CONTEXT ===
                RoleScopeEvidenceState: PROVISIONAL
                RoleScopeDeltaCount: 0
                StrongestRoleScopeDelta: none
                === FRICTION AND APPROVAL HISTORY ===
                ApprovalStatus: UNKNOWN
                === DELEGATED OBJECTIVE CONTEXT ===
                ObjectiveAlignmentEvidence: UNKNOWN
                """;

        SecurityPromptBuildContext buildContext = new SecurityPromptBuildContext(
                null,
                null,
                null,
                List.of(),
                null,
                "user-1",
                BaselineStatus.ESTABLISHED,
                null,
                learningEvidence,
                null,
                StructuredOutputMode.NATIVE_STRUCTURED
        );

        SecurityPromptContractAudit audit = SecurityPromptContractVerifier.audit(systemPrompt, userPrompt, buildContext);

        assertThat(audit.violations()).contains(
                "REQUEST_TIME_MISMATCH",
                "REQUEST_AUTH_VOCABULARY_NOT_SEMANTIC",
                "OBSERVED_AUTH_VOCABULARY_NOT_SEMANTIC",
                "PERSONAL_BASELINE_ESTABLISHED_BUT_SUPPORTING_ONLY_WARNING_PRESENT",
                "ROLE_SCOPE_PROVISIONAL_ZERO_DELTA_CONFLICT",
                "RECENT_PERMISSION_CHANGES_MISSING",
                "HISTORICAL_COMPARABLE_SCOPE_INCORRECT",
                "HISTORICAL_COMPARABLE_SUMMARY_PROVENANCE_MISSING",
                "PATH_COMPARISON_UNRESOLVED_WITH_PERSONAL_EVIDENCE",
                "LEARNING_CARRY_MISSING:CurrentActionFamilyPresentInExpectedRoleScope");
        assertThat(audit.violations()).doesNotContain("LEARNING_CARRY_INCOMPLETE");
        assertThat(audit.renderedRequestSnapshot())
                .containsEntry("currentAccessHour", "10")
                .containsEntry("authenticationType", "UsernamePasswordAuthenticationToken");
        assertThat(audit.renderedLearningSnapshot())
                .containsEntry("historicalComparableScope", "PERSONAL_RETRIEVED_SUBSET")
                .containsEntry("observedPatternEvidenceScope", "PERSONAL_BASELINE_PLUS_PERSONAL_RETRIEVED")
                .containsEntry("currentRequestCombinationSeenCount", 1)
                .containsEntry("currentRequestCombinationEvidenceScope", "PERSONAL_RETRIEVED_SUBSET")
                .containsEntry("currentRequestCombinationComparedDimensions",
                        "accessHour, authenticationType, browser, actionFamily, resourceFamily, pathFamily")
                .containsEntry("currentRequestClosestObservedOverlap", "6/6")
                .containsEntry("strongestCurrentRequestCombinationDelta", "closestOverlap=6/6 | differing=none");
    }
}
