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
package io.contexa.contexacore.std.components.prompt;

import org.assertj.core.groups.Tuple;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SafePromptNormalizationLLMViewComposerTest {

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should normalize whitespace and record a compression ledger")
    void composeShouldNormalizeWhitespaceAndRecordCompressionLedger() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();

        PromptViewComposition composition = composer.compose(
                "Line A  \r\n\r\n\r\nLine B\r\n\r\n",
                "User Line 1   \n\n\nUser Line 2\n",
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.rawSystemPrompt()).isEqualTo("Line A  \n\n\nLine B\n\n");
        assertThat(composition.llmSystemPrompt()).isEqualTo("Line A\n\nLine B");
        assertThat(composition.rawUserPrompt()).isEqualTo("User Line 1   \n\n\nUser Line 2\n");
        assertThat(composition.llmUserPrompt()).isEqualTo("User Line 1\n\nUser Line 2");
        assertThat(composition.compressionLedger().transformationMode()).isEqualTo("NORMALIZE_ONLY");
        assertThat(composition.compressionLedger().rawPromptParity()).isFalse();
        assertThat(composition.compressionLedger().compressionApplied()).isTrue();
        assertThat(composition.compressionLedger().operationCount()).isEqualTo(2);
        assertThat(composition.compressionLedger().savedCharacters()).isPositive();
        assertThat(composition.compressionLedger().savedEstimatedTokens()).isGreaterThanOrEqualTo(0);
    }

    @Test
    @DisplayName("CORTEX_L1_INTERACTIVE_STRICT should preserve every final user prompt line without compacted markers")
    void composeShouldPreserveFullFinalUserPromptForInteractiveStrictProfile() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "User: persona_fin_lead",
                "TenantId: demo",
                "OrganizationId: demo-org",
                "HttpMethod: GET",
                "Path: /admin/api/enterprise/verification/runtime/probe/normal/resource-001",
                "AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT",
                "AuthorizationEffectStageNote: Bridge stamp omitted AuthorizationEffect; final AuthorizationEffect was resolved later from METHOD_INVOCATION_RESULT.",
                "=== CONTEXT COVERAGE ===",
                "CoverageLevel: BUSINESS_AWARE",
                "AvailableFacts:",
                "- Actor identity is available.",
                "- Session identity is available.",
                "- Effective roles are available.",
                "ConfidenceWarnings:",
                "- Observed work pattern is missing; comparisons against previously seen resources or action families remain limited.",
                "- Personal work profile is missing; do not claim the current request matches long-term normal work patterns.",
                "- Role scope profile exists but remains thin, fallback-heavy, or comparison-incomplete; do not treat it as a standalone proof.",
                "=== PERSONAL WORK PROFILE ===",
                "BaselineProfileStatus: PROVISIONAL",
                "PersonalBaselineStatus: LEARNING_IN_PROGRESS",
                "WorkProfileEvidenceState: PROVISIONAL",
                "ObservedHours: 11, 9, 12, 13, 7, 8, 19, 1, 23, 15, 16",
                "ObservedNetworks: 10.10.0",
                "ObservedBrowsers: Chrome/120, Edge/120",
                "CurrentAccessHourPresentInObservedHours: false",
                "CurrentNetworkPresentInObservedNetworks: false",
                "CurrentBrowserPresentInObservedBrowsers: false",
                "LowValueSupportLine1: this is still a source fact and must not be replaced by a marker",
                "LowValueSupportLine2: this is still a source fact and must not be replaced by a marker",
                "=== ROLE AND WORK SCOPE CONTEXT ===",
                "RecentPermissionChanges: UNKNOWN",
                "RoleScopeDeltaCount: UNKNOWN",
                "CurrentActionFamilyPresentInExpectedRoleScope: UNKNOWN",
                "CurrentActionFamilyPresentInDeniedRoleScope: UNKNOWN",
                "=== EXPLICIT MISSING KNOWLEDGE ===",
                "- ContextFieldCoverage: roleScope.expectedResourceFamilies | observations=1 | days=0 | fallback=0% | unknown=100%",
                "- ContextFieldLimitation: roleScope.expectedResourceFamilies | evidence count or time coverage is thin; unknown values remain high");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

        assertThat(composition.llmUserPrompt()).contains("LowValueSupportLine1: this is still a source fact");
        assertThat(composition.llmUserPrompt()).contains("LowValueSupportLine2: this is still a source fact");
        assertThat(composition.llmUserPrompt()).contains("- Actor identity is available.");
        assertThat(composition.llmUserPrompt()).contains("- Session identity is available.");
        assertThat(composition.llmUserPrompt()).contains("- Effective roles are available.");
        assertThat(composition.llmUserPrompt()).doesNotContain("CompactedLineCategories");
        assertThat(composition.llmUserPrompt()).doesNotContain("additional lines compacted");
        assertThat(composition.llmUserPrompt()).doesNotContain("AdditionalConfidenceWarningsCompacted");
        assertThat(composition.llmUserPrompt()).doesNotContain("AdditionalContextTrustWarningsCompacted");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::action)
                .doesNotContain(PromptCompressionAction.SUMMARIZED, PromptCompressionAction.OMITTED);
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should fuse similar past events using summary-first compression")
    void composeShouldFuseSimilarPastEventsWhenThreeOrMoreDocumentsExist() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "Path: /admin/api/security-test/sensitive/resource-001",
                "=== SIMILAR PAST EVENTS ===",
                "HistoricalComparableEvents:",
                "Historical records for context:",
                "[Doc1|type=behavior|user=alice|hour=11|path=/admin/api/security-test/sensitive/resource-001] User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon) Decision: autonomousAction=ALLOW",
                "[Doc2|type=behavior|user=alice|hour=11|path=/admin/api/security-test/sensitive/resource-001] User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:31 (Mon) Decision: autonomousAction=ALLOW",
                "[Doc3|type=behavior|user=alice|hour=11|path=/admin/api/security-test/sensitive/resource-001] User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:32 (Mon) Decision: autonomousAction=ALLOW",
                "=== SESSION NARRATIVE CONTEXT ===",
                "Requests in this session: 3");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.llmUserPrompt()).contains("FusedComparableSummary: 3 comparable records");
        assertThat(composition.llmUserPrompt()).contains("Path=/admin/api/security-test/sensitive/resource-001");
        assertThat(composition.llmUserPrompt()).contains("Browser=Chrome/120");
        assertThat(composition.llmUserPrompt()).contains("OS=Windows");
        assertThat(composition.llmUserPrompt()).contains("Decision=ALLOW");
        assertThat(composition.llmUserPrompt()).contains("+ 1 additional comparable records fused into summary.");
        assertThat(composition.llmUserPrompt()).contains("[Doc1|");
        assertThat(composition.llmUserPrompt()).contains("[Doc2|");
        assertThat(composition.llmUserPrompt()).doesNotContain("[Doc3|");
        assertThat(composition.compressionLedger().transformationMode()).isEqualTo("NORMALIZE_AND_FUSE");
        assertThat(composition.compressionLedger().compressionApplied()).isTrue();
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey)
                .contains("SIMILAR_PAST_EVENTS");
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should compact session narrative and retain key flow anchors")
    void composeShouldCompactSessionNarrativeAndRetainDecisionAnchors() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== SESSION NARRATIVE CONTEXT ===",
                "Requests in this session: 12",
                "SessionTimelineSupport: AUTHZ x12 over 16m",
                "PreviousPath: /admin/api/security-test/sensitive/resource-000",
                "PreviousActionFamily: READ",
                "LastRequestIntervalMs: 4120",
                "SessionActionSequence: [READ, READ, EXPORT, READ]",
                "SessionProtectableSequence: [resource-000, resource-001, resource-002]",
                "BurstPattern: false",
                "LowValueSupportLine1: duplicate payload detail",
                "LowValueSupportLine2: duplicate payload detail",
                "LowValueSupportLine3: duplicate payload detail",
                "=== PERSONAL WORK PROFILE ===",
                "WorkProfileSummary: Window 7d | Observations 24");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.llmUserPrompt()).contains("=== SESSION NARRATIVE CONTEXT ===");
        assertThat(composition.llmUserPrompt()).contains("Requests in this session: 12");
        assertThat(composition.llmUserPrompt()).contains("PreviousPath: /admin/api/security-test/sensitive/resource-000");
        assertThat(composition.llmUserPrompt()).contains("LastRequestIntervalMs: 4120");
        assertThat(composition.llmUserPrompt()).contains("SessionActionSequence: [READ, READ, EXPORT, READ]");
        assertThat(composition.llmUserPrompt()).contains("SessionProtectableSequence: [resource-000, resource-001, resource-002]");
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should compact personal work profile and retain baseline anchors")
    void composeShouldCompactPersonalWorkProfileAndRetainBaselineAnchors() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== PERSONAL WORK PROFILE ===",
                "WorkProfileEvidenceState: PROVISIONAL",
                "WorkProfileSummary: Window 7d | Observations 42",
                "FrequentProtectableResources: sensitive/resource-001=14, sensitive/resource-002=9",
                "FrequentActionFamilies: READ=35, EXPORT=7",
                "NormalAccessHours: 09-11=60%, 13-16=30%",
                "NormalAccessDays: MON=40%, TUE=35%, WED=25%",
                "ProtectableInvocationDensity: 5.2/day",
                "NormalReadWriteExportRatio: 80/10/10",
                "TopPaths: /resource-001, /resource-002",
                "TopHours: 09, 10, 14",
                "TopDays: MON, TUE",
                "TopBrowsers: Chrome/120",
                "TopOperatingSystems: Windows 11",
                "ContextEvidenceLimitation: history only covers 7d",
                "ContextTrustLimitation: no delegated objective data",
                "ContextTrustWarning: treat as provisional baseline",
                "LowValueSupportLine1: verbose derived narrative",
                "LowValueSupportLine2: verbose derived narrative");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.llmUserPrompt()).contains("=== PERSONAL WORK PROFILE ===");
        assertThat(composition.llmUserPrompt()).contains("WorkProfileEvidenceState: PROVISIONAL");
        assertThat(composition.llmUserPrompt()).contains("WorkProfileSummary: Window 7d | Observations 42");
        assertThat(composition.llmUserPrompt()).contains("FrequentProtectableResources: sensitive/resource-001=14, sensitive/resource-002=9");
        assertThat(composition.llmUserPrompt()).contains("FrequentActionFamilies: READ=35, EXPORT=7");
        assertThat(composition.llmUserPrompt()).contains("NormalReadWriteExportRatio: 80/10/10");
        assertThat(composition.llmUserPrompt()).contains("ContextTrustWarning: treat as provisional baseline");
        assertThat(composition.llmUserPrompt()).contains("additional lines compacted.");
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueSupportLine1: verbose derived narrative");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(Tuple.tuple("PERSONAL_WORK_PROFILE", PromptCompressionAction.SUMMARIZED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should retain indented baseline delta lines under personal work profile support")
    void composeShouldRetainIndentedBaselineDeltaLines() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== PERSONAL WORK PROFILE ===",
                "HistoricalBaselineSupport:",
                "  BaselineProfileStatus: ESTABLISHED",
                "  PersonalBaselineStatus: ESTABLISHED",
                "  BaselineObservations: 20",
                "  CurrentVsObservedDeltaCount: 2",
                "  StrongestCurrentVsObservedDelta: access hour outside observed hours",
                "  CurrentVsObservedDeltaSummary: access hour outside observed hours | path family unseen in observed paths",
                "  WorkProfileEvidenceState: TRUSTED",
                "  CurrentRequestCombinationSeenCount: 0",
                "  CurrentRequestCombinationEvidenceScope: PERSONAL_RETRIEVED_SUBSET",
                "  CurrentRequestCombinationComparedDimensions: accessHour, authenticationType, browser, actionFamily, resourceFamily, pathFamily",
                "  CurrentRequestClosestObservedOverlap: 5/6",
                "  StrongestCurrentRequestCombinationDelta: closestOverlap=5/6 | differing=pathFamily",
                "  CurrentRequestCombinationSummary: hour=16 | auth=PASSWORD | browser=Chrome/120 | action=READ | resource=SENSITIVE | path=/admin/api/*",
                "  ObservedComparableCombination1: count=1 | hour=10 | auth=PASSWORD | browser=Chrome/120 | action=READ | resource=SENSITIVE | path=/admin/api/*",
                "  CurrentAccessHour: 16",
                "  CurrentAccessHourPresentInObservedHours: false",
                "  CurrentDayOfWeek: 6",
                "  CurrentDayPresentInObservedDays: true",
                "  CurrentNetwork: 10.10.0.0/24",
                "  CurrentNetworkPresentInObservedNetworks: true",
                "  CurrentBrowser: Chrome/120",
                "  CurrentBrowserPresentInObservedBrowsers: true",
                "  CurrentOperatingSystem: Windows",
                "  CurrentOperatingSystemPresentInObservedOperatingSystems: true",
                "  CurrentPathFamily: /admin/api/*",
                "  CurrentPathPresentInObservedPaths: false",
                "  CurrentAuthenticationType: PASSWORD",
                "  CurrentAuthenticationTypePresentInObservedAuthTypes: true",
                "  CurrentActionFamily: READ",
                "  CurrentActionFamilyPresentInObservedActions: true",
                "  CurrentResourceFamily: SENSITIVE",
                "  CurrentResourceFamilyPresentInObservedResources: true",
                "  ObservedHours: 8, 9, 10, 11",
                "  ObservedDays: 6",
                "  LowValueSupportLine1: verbose derived narrative",
                "  LowValueSupportLine2: verbose derived narrative");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.llmUserPrompt()).contains("BaselineProfileStatus: ESTABLISHED");
        assertThat(composition.llmUserPrompt()).contains("BaselineObservations: 20");
        assertThat(composition.llmUserPrompt()).contains("CurrentVsObservedDeltaCount: 2");
        assertThat(composition.llmUserPrompt()).contains("StrongestCurrentVsObservedDelta: access hour outside observed hours");
        assertThat(composition.llmUserPrompt()).contains("CurrentVsObservedDeltaSummary: access hour outside observed hours | path family unseen in observed paths");
        assertThat(composition.llmUserPrompt()).contains("WorkProfileEvidenceState: TRUSTED");
        assertThat(composition.llmUserPrompt()).contains("CurrentRequestCombinationSeenCount: 0");
        assertThat(composition.llmUserPrompt()).contains("CurrentRequestCombinationEvidenceScope: PERSONAL_RETRIEVED_SUBSET");
        assertThat(composition.llmUserPrompt()).contains("CurrentRequestCombinationComparedDimensions: accessHour, authenticationType, browser, actionFamily, resourceFamily, pathFamily");
        assertThat(composition.llmUserPrompt()).contains("CurrentRequestClosestObservedOverlap: 5/6");
        assertThat(composition.llmUserPrompt()).contains("StrongestCurrentRequestCombinationDelta: closestOverlap=5/6 | differing=pathFamily");
        assertThat(composition.llmUserPrompt()).contains("ObservedComparableCombination1: count=1 | hour=10 | auth=PASSWORD | browser=Chrome/120 | action=READ | resource=SENSITIVE | path=/admin/api/*");
        assertThat(composition.llmUserPrompt()).contains("CurrentAccessHour: 16");
        assertThat(composition.llmUserPrompt()).contains("CurrentAccessHourPresentInObservedHours: false");
        assertThat(composition.llmUserPrompt()).contains("CurrentPathPresentInObservedPaths: false");
        assertThat(composition.llmUserPrompt()).contains("CurrentAuthenticationTypePresentInObservedAuthTypes: true");
        assertThat(composition.llmUserPrompt()).contains("CurrentActionFamilyPresentInObservedActions: true");
        assertThat(composition.llmUserPrompt()).contains("CurrentResourceFamilyPresentInObservedResources: true");
        assertThat(composition.llmUserPrompt()).contains("ObservedHours: 8, 9, 10, 11");
        assertThat(composition.llmUserPrompt()).contains("ObservedDays: 6");
        assertThat(composition.llmUserPrompt()).contains("CompactedLineCategories:");
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueSupportLine1: verbose derived narrative");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(Tuple.tuple("PERSONAL_WORK_PROFILE", PromptCompressionAction.SUMMARIZED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should preserve current request, friction, delegation, and missing-knowledge anchors under compact budget")
    void composeShouldPreserveCurrentRequestFrictionDelegationAndMissingKnowledgeAnchorsUnderCompactBudget() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String densePad = "approval-and-scope-padding-".repeat(80);
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "User is requesting GET /admin/api/security-test/sensitive/self-sensitive-1 at 23:17.",
                "AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT",
                "AuthorizationEffectStageNote: Bridge stamp omitted AuthorizationEffect; final AuthorizationEffect was resolved later from METHOD_INVOCATION_RESULT.",
                "MfaVerified: true",
                "FailedLoginAttempts: 0",
                "CurrentRequestContextPad01: " + densePad,
                "CurrentRequestContextPad02: " + densePad,
                "=== FRICTION AND APPROVAL HISTORY ===",
                "ApprovalRequired: false",
                "ApprovalGranted: false",
                "ApprovalMissing: false",
                "ApprovalStatus: NONE",
                "LowValueFrictionLine: verbose support",
                "=== DELEGATED OBJECTIVE CONTEXT ===",
                "Delegated: false",
                "ObjectiveFamily: SECURITY_TEST",
                "ObjectiveSummary: Validate zero-trust judgment.",
                "ObjectiveAlignmentEvidence: objective matches self security validation flow.",
                "LowValueDelegationLine: verbose support",
                "=== EXPLICIT MISSING KNOWLEDGE ===",
                "BaselineGapSupport:",
                "  STATUS: PROVISIONAL",
                "  IMPACT: Learning evidence is still partial.",
                "  BASELINE EVIDENCE CONSTRAINTS:",
                "- ConfidenceWarning: supporting evidence is reference-only.",
                "- ContextEvidenceLimitation: recent work history is thin.");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_COMPACT);

        assertThat(composition.llmUserPrompt()).contains("User is requesting GET /admin/api/security-test/sensitive/self-sensitive-1 at 23:17.");
        assertThat(composition.llmUserPrompt()).contains("AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT");
        assertThat(composition.llmUserPrompt()).contains("FailedLoginAttempts: 0");
        assertThat(composition.llmUserPrompt()).contains("ApprovalStatus: NONE");
        assertThat(composition.llmUserPrompt()).contains("ObjectiveAlignmentEvidence: objective matches self security validation flow.");
        assertThat(composition.llmUserPrompt()).contains("- ConfidenceWarning: supporting evidence is reference-only.");
        assertThat(composition.llmUserPrompt()).contains("- ContextEvidenceLimitation: recent work history is thin.");
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should retain explicit missing knowledge under compact budget")
    void composeShouldRetainExplicitMissingKnowledgeUnderCompactBudget() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String densePad = "request-context-padding-".repeat(120);
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "RequestPath: /admin/api/security-test/sensitive/resource-001",
                "CurrentRequestContextPad01: " + densePad,
                "CurrentRequestContextPad02: " + densePad,
                "CurrentRequestContextPad03: " + densePad,
                "=== PERSONAL WORK PROFILE ===",
                "HistoricalBaselineSupport:",
                "  BaselineProfileStatus: SPARSE_PERSONAL_HISTORY",
                "  BaselineSupportSummary: Personal evidence remains sparse.",
                "=== EXPLICIT MISSING KNOWLEDGE ===",
                "BaselineGapSupport:",
                "  STATUS: SPARSE_PERSONAL_HISTORY",
                "  IMPACT: Personal history remains limited for direct comparison.",
                "  BASELINE EVIDENCE CONSTRAINTS:",
                "- Sparse personal history is uncertainty, not proof of compromise or legitimacy by itself.",
                "- ContextTrustLimitation: Supporting baseline remains reference-only.");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_COMPACT);

        assertThat(composition.llmUserPrompt()).contains("=== EXPLICIT MISSING KNOWLEDGE ===");
        assertThat(composition.llmUserPrompt()).contains("BaselineGapSupport:");
        assertThat(composition.llmUserPrompt()).contains("STATUS: SPARSE_PERSONAL_HISTORY");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .doesNotContain(Tuple.tuple("EXPLICIT_MISSING_KNOWLEDGE_BUDGET_OMISSION", PromptCompressionAction.OMITTED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should retain historical comparable and supporting learning sections under compact budget")
    void composeShouldRetainHistoricalComparableAndSupportingLearningUnderCompactBudget() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String densePad = "request-context-padding-".repeat(120);
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "RequestPath: /admin/api/security-test/sensitive/resource-001",
                "CurrentRequestContextPad01: " + densePad,
                "CurrentRequestContextPad02: " + densePad,
                "CurrentRequestContextPad03: " + densePad,
                "=== SIMILAR PAST EVENTS ===",
                "HistoricalComparableScope: PERSONAL_RETRIEVED_SUBSET",
                "HistoricalComparableCount: 1",
                "HistoricalComparableSummary: Records=1 | Paths=/admin/api/* | Hours=9",
                "ComparableExample1: 09:00 Chrome/120 Windows READ /admin/api/security-test/sensitive/resource-001",
                "=== SUPPORTING LEARNING CONTEXT ===",
                "SupportingEvidenceMode: REFERENCE_ONLY",
                "SupportingEvidenceNeverReplacesPersonalBaseline: true",
                "SupportingBaselineStatus: AVAILABLE_REFERENCE",
                "SupportingBaselineSummary: Cohort reference baseline available for comparison only.",
                "SupportingComparableCount: 2",
                "SupportingComparableSummary: Records=2 | Path=/admin/api/* | Hour=9 | Browser=Chrome/120",
                "SupportingComparableExample1: 09:10 Chrome/120 Windows READ /admin/api/security-test/sensitive/resource-001",
                "SupportingEvidenceConstraint: Use supporting learning only as reference context, never as proof of an established personal norm.");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_COMPACT);

        assertThat(composition.llmUserPrompt()).contains("=== SIMILAR PAST EVENTS ===");
        assertThat(composition.llmUserPrompt()).contains("HistoricalComparableScope: PERSONAL_RETRIEVED_SUBSET");
        assertThat(composition.llmUserPrompt()).contains("HistoricalComparableCount: 1");
        assertThat(composition.llmUserPrompt()).contains("ComparableExample1:");
        assertThat(composition.llmUserPrompt()).contains("=== SUPPORTING LEARNING CONTEXT ===");
        assertThat(composition.llmUserPrompt()).contains("SupportingBaselineStatus: AVAILABLE_REFERENCE");
        assertThat(composition.llmUserPrompt()).contains("SupportingComparableCount: 2");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .doesNotContain(
                        Tuple.tuple("SIMILAR_PAST_EVENTS_BUDGET_OMISSION", PromptCompressionAction.OMITTED),
                        Tuple.tuple("SUPPORTING_LEARNING_CONTEXT_BUDGET_OMISSION", PromptCompressionAction.OMITTED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should compact role, friction, and threat sections summary-first")
    void composeShouldCompactRoleScopeFrictionAndThreatSections() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== ROLE AND WORK SCOPE CONTEXT ===",
                "RoleScopeEvidenceState: PROVISIONAL",
                "RoleScopeSummary: Effective roles ADMIN, PENDING_ANALYSIS | Current action family READ",
                "RoleScopeDeltaCount: 1",
                "StrongestRoleScopeDelta: resource family outside expected role scope",
                "RoleScopeDeltaSummary: resource family outside expected role scope",
                "CurrentResourceFamily: sensitive",
                "CurrentActionFamily: READ",
                "ExpectedResourceFamilies: sensitive, critical",
                "ExpectedActionFamilies: READ",
                "ForbiddenResourceFamilies: export",
                "ForbiddenActionFamilies: DELETE",
                "CurrentResourceFamilyPresentInExpectedRoleScope: true",
                "CurrentActionFamilyPresentInExpectedRoleScope: true",
                "RecentPermissionChanges: none",
                "TemporaryElevation: null",
                "ElevatedPrivilegeWindowActive: false",
                "LowValueRoleLine: verbose comparison",
                "LowValueRoleLine2: verbose comparison",
                "=== FRICTION AND APPROVAL HISTORY ===",
                "FrictionSummary: MFA recently completed and no approval ticket is present",
                "RecentChallengeCount: 1",
                "RecentBlockCount: 0",
                "RecentEscalationCount: 0",
                "ApprovalRequired: false",
                "ApprovalGranted: false",
                "ApprovalMissing: false",
                "ApprovalStatus: NONE",
                "ApprovalLineage: []",
                "PendingApproverRoles: []",
                "BreakGlass: false",
                "RecentDeniedAccessCount: 0",
                "BlockedUser: false",
                "LowValueFrictionLine: verbose support",
                "=== OUTCOME AND REASONING MEMORY ===",
                "ReasoningMemorySummary: similar read-only cases usually ended in ALLOW with provisional context",
                "ReinforcedCaseCount: 3",
                "HardNegativeCaseCount: 1",
                "FalseNegativeCaseCount: 0",
                "KnowledgeAssistedCaseCount: 2",
                "FreshnessState: FRESH",
                "ReasoningState: ACTIVE",
                "MemoryRiskProfile: MODERATE",
                "MatchedSignalKeys: [BASELINE_ONLY]",
                "MemoryGuardrails: [NO_CROSS_TENANT]",
                "XaiLinkedFacts: [baseline, scope]",
                "LowValueThreatLine: verbose support");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.llmUserPrompt()).contains("RoleScopeSummary: Effective roles ADMIN, PENDING_ANALYSIS | Current action family READ");
        assertThat(composition.llmUserPrompt()).contains("RoleScopeDeltaCount: 1");
        assertThat(composition.llmUserPrompt()).contains("StrongestRoleScopeDelta: resource family outside expected role scope");
        assertThat(composition.llmUserPrompt()).contains("RoleScopeDeltaSummary: resource family outside expected role scope");
        assertThat(composition.llmUserPrompt()).contains("CurrentResourceFamilyPresentInExpectedRoleScope: true");
        assertThat(composition.llmUserPrompt()).contains("CurrentActionFamilyPresentInExpectedRoleScope: true");
        assertThat(composition.llmUserPrompt()).contains("FrictionSummary: MFA recently completed and no approval ticket is present");
        assertThat(composition.llmUserPrompt()).contains("ReasoningMemorySummary: similar read-only cases usually ended in ALLOW with provisional context");
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueRoleLine:");
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueFrictionLine:");
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueThreatLine:");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(
                        Tuple.tuple("ROLE_SCOPE", PromptCompressionAction.SUMMARIZED),
                        Tuple.tuple("FRICTION_AND_APPROVAL", PromptCompressionAction.SUMMARIZED),
                        Tuple.tuple("OUTCOME_AND_REASONING_MEMORY", PromptCompressionAction.SUMMARIZED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should compact coverage-heavy cold-start prompts without dropping critical gaps")
    void composeShouldCompactCoverageHeavyColdStartPrompt() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "CurrentHour: 19",
                "User: admin",
                "HttpMethod: GET",
                "FailedLoginAttempts: 0",
                "NewDevice: true",
                "NewSession: false",
                "NewUser: false",
                "MfaVerified: true",
                "Path: /admin/api/security-test/sensitive/resource-001",
                "AuthorizationContext:",
                "  AuthorizationEffectProvenance: METHOD_INVOCATION_RESULT",
                "  AuthorizationEffectStageNote: Bridge stamp omitted AuthorizationEffect; final AuthorizationEffect was resolved later from METHOD_INVOCATION_RESULT.",
                "=== BRIDGE RESOLUTION CONTEXT ===",
                "BridgeCompletenessLevel: AUTHORIZATION_CONTEXT",
                "BridgeCompletenessSummary: Bridge completeness reached authentication and partial authorization context for the current request.",
                "BridgeAuthenticationSource: SECURITY_CONTEXT",
                "BridgeAuthorizationSource: SECURITY_CONTEXT",
                "BridgeMissingContexts: AUTHORIZATION_EFFECT",
                "BridgeRemediationHints: Populate an explicit authorization effect such as ALLOW or DENY for the current request.",
                "=== CONTEXT COVERAGE ===",
                "CoverageLevel: BUSINESS_AWARE",
                "CoverageSummary: Business-aware context is available for role, resource, and session reasoning. Bridge coverage: AUTHORIZATION_CONTEXT.",
                "AvailableFacts:",
                "- Actor identity is available.",
                "- Session identity is available.",
                "- Effective roles are available.",
                "- Authorization scope is available.",
                "MissingCriticalFacts:",
                "- Bridge missing context: AUTHORIZATION_EFFECT.",
                "- Personal work profile is missing.",
                "RemediationHints:",
                "- Collect protectable access history so observed work patterns can be inferred.",
                "- Populate an explicit authorization effect such as ALLOW or DENY for the current request.",
                "ConfidenceWarnings:",
                "- Observed work pattern is missing; comparisons against previously seen resources or action families remain limited.",
                "- Personal work profile is missing; do not claim the current request matches long-term normal work patterns.",
                "- Role scope profile exists but remains thin, fallback-heavy, or comparison-incomplete; do not treat it as a standalone proof of authorized business scope.",
                "- Friction and approval history is missing; do not assume prior approval, challenge, or denial precedent exists.",
                "=== IDENTITY AND ROLE CONTEXT ===",
                "UserId: admin",
                "PrincipalType: UNIFIEDCUSTOMUSERDETAILS",
                "EffectiveRoles: DEVELOPER, USER, PENDING_ANALYSIS, MANAGER, ADMIN",
                "EffectivePermissions: role.user, role.developer, role.manager, role.pending.analysis, role.admin",
                "AuthorizationEffect: ALLOW",
                "=== AUTHENTICATION AND ASSURANCE CONTEXT ===",
                "SessionId: session-1",
                "ClientIp: 0:0:0:0:0:0:0:1",
                "AuthenticationType: ZEROTRUSTAUTHENTICATIONTOKEN",
                "MfaVerified: true",
                "FailedLoginAttempts: 0",
                "RecentRequestCount: 2",
                "NewSession: false",
                "NewUser: false",
                "NewDevice: true",
                "=== RESOURCE AND ACTION CONTEXT ===",
                "RequestPath: /admin/api/security-test/sensitive/resource-001",
                "HttpMethod: GET",
                "ActionFamily: READ",
                "BusinessLabel: Sensitive Security Test Resource resource-001",
                "Sensitivity: HIGH",
                "SensitiveResource: true");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.rawUserPrompt()).contains("AvailableFacts:");
        assertThat(composition.rawUserPrompt()).contains("- Bridge missing context: AUTHORIZATION_EFFECT.");
        assertThat(composition.llmUserPrompt()).contains("CoverageLevel: BUSINESS_AWARE");
        assertThat(composition.llmUserPrompt()).contains("CoverageSummary: Business-aware context is available for role, resource, and session reasoning. Bridge coverage: AUTHORIZATION_CONTEXT.");
        assertThat(composition.llmUserPrompt()).contains("MissingCriticalFacts:");
        assertThat(composition.llmUserPrompt()).doesNotContain("- Bridge missing context: AUTHORIZATION_EFFECT.");
        assertThat(composition.llmUserPrompt()).contains("- Personal work profile is missing.");
        assertThat(composition.llmUserPrompt()).contains("AvailableFactsCompacted: 4");
        assertThat(composition.llmUserPrompt()).contains("RemediationHintsCompacted: 2");
        assertThat(composition.llmUserPrompt()).contains("AdditionalConfidenceWarningsCompacted: 1");
        assertThat(composition.llmUserPrompt()).contains("RequestPath: /admin/api/security-test/sensitive/resource-001");
        assertThat(composition.llmUserPrompt()).contains("HttpMethod: GET");
        assertThat(composition.llmUserPrompt()).contains("BusinessLabel: Sensitive Security Test Resource resource-001");
        assertThat(composition.llmUserPrompt()).contains("Sensitivity: HIGH");
        assertThat(composition.llmUserPrompt()).doesNotContain("AvailableFacts:\n- Actor identity is available.");
        assertThat(composition.llmUserPrompt()).doesNotContain("RemediationHints:\n-");
        assertThat(composition.llmUserPrompt()).doesNotContain("BridgeRemediationHints:");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(
                        Tuple.tuple("BRIDGE_RESOLUTION", PromptCompressionAction.SUMMARIZED),
                        Tuple.tuple("CONTEXT_COVERAGE", PromptCompressionAction.SUMMARIZED),
                        Tuple.tuple("AUTHENTICATION_AND_ASSURANCE", PromptCompressionAction.SUMMARIZED),
                        Tuple.tuple("EXPLICIT_MISSING_KNOWLEDGE", PromptCompressionAction.OMITTED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should omit supporting sections with the compact budget ladder")
    void composeShouldOmitSupportingSectionsWhenCompactBudgetStillExceedsLimit() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String densePad = "critical-access-context-padding-".repeat(90);
        String userPrompt = String.join("\n",
                "=== CURRENT REQUEST AND EVENT ===",
                "RequestPath: /admin/api/security-test/critical/resource-991",
                "ClientIp: 192.168.1.100",
                "MfaVerified: true",
                "Sensitivity: HIGH",
                "AuthorizationEffect: ALLOW",
                "CurrentRequestContextPad01: " + densePad,
                "CurrentRequestContextPad02: " + densePad,
                "CurrentRequestContextPad03: " + densePad,
                "=== PEER COHORT DELTA ===",
                "PeerCohortSummary: same department peers usually stay inside /normal and /sensitive resources",
                "CohortPreferredResources: /admin/api/security-test/normal/resource-001, /admin/api/security-test/sensitive/resource-001",
                "CohortPreferredActionFamilies: READ, EXPORT",
                "CurrentActionFamilyPresentInPeerPreferredActions: false",
                "CurrentResourcePresentInPeerPreferredResources: false",
                "=== OUTCOME AND REASONING MEMORY ===",
                "ReasoningMemorySummary: previous similar cases were mixed and memory should only be supporting context",
                "ReinforcedCaseCount: 12",
                "HardNegativeCaseCount: 4",
                "FalseNegativeCaseCount: 1",
                "KnowledgeAssistedCaseCount: 8",
                "FreshnessState: STABLE",
                "ReasoningState: ACTIVE",
                "MemoryRiskProfile: ELEVATED",
                "MatchedSignalKeys: [BASELINE_ONLY, MEMORY_SUPPORT]",
                "MemoryGuardrails: [NO_CROSS_TENANT, PURPOSE_BOUND]",
                "XaiLinkedFacts: [baseline, role scope, session, history]",
                "=== PERSONAL WORK PROFILE ===",
                "WorkProfileEvidenceState: PROVISIONAL",
                "WorkProfileSummary: Window 7d | Observations 2",
                "FrequentProtectableResources: /critical/resource-991, /critical/resource-992, /critical/resource-993, /critical/resource-994, /critical/resource-995",
                "FrequentActionFamilies: READ=80, EXPORT=20",
                "NormalAccessHours: 09-11=60%, 13-16=40%",
                "NormalAccessDays: MON=50%, WED=50%",
                "TopBrowsers: Chrome/120, Edge/120",
                "TopOperatingSystems: Windows 11, Windows 11 VDI",
                "ContextTrustWarning: treat as provisional baseline");

        PromptViewComposition composition = composer.compose(
                "system",
                userPrompt,
                PromptBudgetProfile.CORTEX_L1_COMPACT);

        assertThat(composition.llmUserPrompt()).contains("RequestPath: /admin/api/security-test/critical/resource-991");
        assertThat(composition.llmUserPrompt()).contains("=== PERSONAL WORK PROFILE ===");
        assertThat(composition.llmUserPrompt()).contains("WorkProfileEvidenceState: PROVISIONAL");
        assertThat(composition.llmUserPrompt()).contains("WorkProfileSummary: Window 7d | Observations 2");
        assertThat(composition.llmUserPrompt()).doesNotContain("=== PEER COHORT DELTA ===");
        assertThat(composition.llmUserPrompt()).doesNotContain("=== OUTCOME AND REASONING MEMORY ===");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(
                        Tuple.tuple("PEER_COHORT_DELTA_BUDGET", PromptCompressionAction.OMITTED),
                        Tuple.tuple("OUTCOME_AND_REASONING_MEMORY_BUDGET_OMISSION", PromptCompressionAction.OMITTED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should compact the system prompt when a non-expanding standard budget overflows")
    void composeShouldCompactSystemPromptWhenStandardBudgetIsExceeded() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String oversizedSystemPrompt = String.join("\n",
                "You are a Zero Trust security analyst AI.",
                "Detailed instruction: " + "context-heavy-contract-".repeat(900),
                "<output_format>",
                "{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\"},\"confidence\":{\"type\":\"number\"},\"reasoning\":{\"type\":\"string\"}}}",
                "</output_format>",
                "<context>",
                "governance-metadata",
                "</context>");

        PromptViewComposition composition = composer.compose(
                oversizedSystemPrompt,
                "=== CURRENT REQUEST AND EVENT ===\nRequestPath: /admin/api/enterprise/verification/runtime/probe/sensitive/resource-001",
                PromptBudgetProfile.CORTEX_L1_STANDARD);

        assertThat(composition.llmSystemPrompt().length()).isLessThanOrEqualTo(composition.rawSystemPrompt().length());
        assertThat(composition.llmSystemPrompt()).contains("You are a Zero Trust security analyst AI.");
        assertThat(composition.llmSystemPrompt()).contains("Detailed instruction:");
        assertThat(composition.llmSystemPrompt()).contains("<output_format>");
        assertThat(composition.llmSystemPrompt()).contains("<context>");
        assertThat(composition.llmSystemPrompt()).doesNotContain("...");
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer should preserve latest security recipe lines when compacting the system prompt")
    void composeShouldPreserveLatestSecurityRecipeLinesWhenCompactingSystemPrompt() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String securitySystemPrompt = String.join("\n",
                "You are a Zero Trust security analyst AI.",
                "ANALYSIS ORDER:",
                "1. Establish the overall request story from current request, resource sensitivity, session continuity, baseline maturity, role scope, approval lineage, delegated objective, and threat memory together.",
                "2. Then explicitly scan current-vs-observed, current-vs-expected, and current-vs-denied comparison labels before deciding.",
                "3. Reconcile subtle deltas against legitimate explanations, approval history, and delegated scope.",
                "4. If bridge stage notes or coverage warnings conflict with later canonical labels, prefer the most final canonical field.",
                "5. If one or more subtle deltas remain unresolved, explicitly account for the strongest delta in your reasoning or uncertainty wording.",
                "6. Do not tunnel on one isolated weak mismatch by itself.",
                "Action semantics: ALLOW=legitimate fit with established evidence, CHALLENGE=plausible but under-verified, ESCALATE=incomplete or ambiguous, BLOCK=clearly malicious or harmful.",
                "If comparison labels such as CurrentAccessHourPresentInObservedHours or CurrentPathPresentInObservedPaths indicate a mismatch, do not ignore that subtle delta.",
                "But do not let one weak mismatch override a clearly legitimate whole story unless the mismatch remains unresolved after considering approval, delegated scope, comparable history, and baseline maturity together.",
                "<context>",
                "governance-metadata",
                "</context>");

        PromptViewComposition composition = composer.compose(
                securitySystemPrompt,
                "=== CURRENT REQUEST AND EVENT ===\nRequestPath: /admin/api/security-test/sensitive/resource-001",
                PromptBudgetProfile.CORTEX_L1_DECISION_COMPACT);

        assertThat(composition.llmSystemPrompt()).contains("ANALYSIS ORDER:");
        assertThat(composition.llmSystemPrompt()).contains("Do not tunnel on one isolated weak mismatch by itself.");
        assertThat(composition.llmSystemPrompt()).contains("do not ignore that subtle delta.");
        assertThat(composition.llmSystemPrompt()).contains("<context>");
        assertThat(composition.llmSystemPrompt()).doesNotContain("...");
    }
}


