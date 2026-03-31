package io.contexa.contexacore.std.components.prompt;

import org.assertj.core.groups.Tuple;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SafePromptNormalizationLLMViewComposerTest {

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer는 공백만 정규화하고 압축 ledger를 남겨야 한다")
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
    @DisplayName("SafePromptNormalizationLLMViewComposer는 SIMILAR PAST EVENTS를 summary-first로 융합해야 한다")
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
    @DisplayName("SafePromptNormalizationLLMViewComposer는 SESSION NARRATIVE를 압축하되 핵심 흐름은 보존해야 한다")
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
        assertThat(composition.llmUserPrompt()).contains("additional lines compacted.");
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueSupportLine1");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(Tuple.tuple("SESSION_NARRATIVE", PromptCompressionAction.SUMMARIZED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer는 PERSONAL WORK PROFILE을 압축하되 baseline anchor는 유지해야 한다")
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
        assertThat(composition.llmUserPrompt()).doesNotContain("LowValueSupportLine1");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(Tuple.tuple("PERSONAL_WORK_PROFILE", PromptCompressionAction.SUMMARIZED));
    }

    @Test
    @DisplayName("SafePromptNormalizationLLMViewComposer는 role, friction, threat 섹션도 summary-first로 압축해야 한다")
    void composeShouldCompactRoleScopeFrictionAndThreatSections() {
        SafePromptNormalizationLLMViewComposer composer = new SafePromptNormalizationLLMViewComposer();
        String userPrompt = String.join("\n",
                "=== ROLE AND WORK SCOPE CONTEXT ===",
                "RoleScopeEvidenceState: PROVISIONAL",
                "RoleScopeSummary: Effective roles ADMIN, PENDING_ANALYSIS | Current action family READ",
                "CurrentResourceFamily: sensitive",
                "CurrentActionFamily: READ",
                "ExpectedResourceFamilies: sensitive, critical",
                "ExpectedActionFamilies: READ",
                "ForbiddenResourceFamilies: export",
                "ForbiddenActionFamilies: DELETE",
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
    @DisplayName("SafePromptNormalizationLLMViewComposer는 compact profile에서 supporting 섹션을 budget ladder로 생략해야 한다")
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
        assertThat(composition.llmUserPrompt()).doesNotContain("=== PEER COHORT DELTA ===");
        assertThat(composition.llmUserPrompt()).doesNotContain("=== OUTCOME AND REASONING MEMORY ===");
        assertThat(composition.compressionLedger().records())
                .extracting(PromptCompressionRecord::scopeKey, PromptCompressionRecord::action)
                .contains(
                        Tuple.tuple("PEER_COHORT_DELTA_BUDGET", PromptCompressionAction.OMITTED),
                        Tuple.tuple("OUTCOME_AND_REASONING_MEMORY_BUDGET_OMISSION", PromptCompressionAction.OMITTED));
    }
}