package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PromptContextComposerTest {

    @Test
    void composeShouldRenderCoverageIdentityResourceAndDelegationSections() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder()
                        .userId("alice")
                        .externalSubjectId("ext-alice")
                        .organizationId("tenant-acme")
                        .tenantId("tenant-acme")
                        .department("finance")
                        .position("Senior Analyst")
                        .bridgeSubjectKey("security_context:tenant-acme:ext-alice")
                        .roleSet(List.of("ANALYST"))
                        .authoritySet(List.of("report.read"))
                        .build())
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-1")
                        .authenticationType("SESSION")
                        .authenticationAssurance("HIGH")
                        .mfaVerified(true)
                        .recentMfaFailureCount(2)
                        .lastMfaUsedAt("2026-03-24T08:58:00")
                        .recentRequestCount(5)
                        .recentChallengeCount(2)
                        .recentBlockCount(1)
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .businessLabel("Customer Export Report")
                        .sensitivity("HIGH")
                        .actionFamily("READ")
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .summary("Session age minutes: 24 | Previous path: /api/customer/list | Previous action family: READ | Last request interval ms: 800")
                        .sessionAgeMinutes(24)
                        .previousPath("/api/customer/list")
                        .previousActionFamily("READ")
                        .lastRequestIntervalMs(800L)
                        .sessionActionSequence(List.of("READ", "READ", "EXPORT"))
                        .sessionProtectableSequence(List.of("/api/customer/list", "/api/customer/export"))
                        .burstPattern(false)
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder()
                        .effectiveRoles(List.of("ANALYST"))
                        .effectivePermissions(List.of("report.read"))
                        .scopeTags(List.of("customer_data"))
                        .policyId("policy-1")
                        .policyVersion("2026.03")
                        .build())
                .observedScope(CanonicalSecurityContext.ObservedScope.builder()
                        .profileSource("PROTECTABLE_ACCESS_HISTORY")
                        .summary("Current resource is rare compared with observed work history.")
                        .recentProtectableAccessCount(12)
                        .recentDeniedAccessCount(1)
                        .frequentResources(List.of("/api/customer/list", "/api/customer/search"))
                        .frequentActionFamilies(List.of("READ", "EXPORT"))
                        .rareCurrentResource(true)
                        .build())
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Frequent protectable resources: /api/customer/list, /api/customer/search | Frequent action families: READ, EXPORT")
                        .frequentProtectableResources(List.of("/api/customer/list", "/api/customer/search"))
                        .frequentActionFamilies(List.of("READ", "EXPORT"))
                        .protectableResourceHeatmap(List.of("/api/customer/list=9", "/api/customer/export=3"))
                        .normalAccessHours(List.of(9, 10, 11))
                        .normalRequestRate(2.5d)
                        .normalReadWriteExportRatio("80:15:5")
                        .protectableInvocationDensity(0.6d)
                        .seasonalBusinessProfile("Quarter-end finance export review window")
                        .longTailLegitimateTasks(List.of("Quarter close export attestation"))
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Effective roles: ANALYST | Scope tags: customer_data | Resource family drift: true")
                        .currentResourceFamily("REPORT")
                        .currentActionFamily("EXPORT")
                        .expectedResourceFamilies(List.of("REPORT"))
                        .expectedActionFamilies(List.of("READ", "EXPORT"))
                        .normalApprovalPatterns(List.of("Export requires manager approval"))
                        .recentPermissionChanges(List.of("Temporary export permission granted yesterday"))
                        .resourceFamilyDrift(true)
                        .actionFamilyDrift(false)
                        .temporaryElevation(true)
                        .temporaryElevationReason("Emergency customer export review")
                        .elevatedPrivilegeWindowActive(true)
                        .elevationWindowSummary("Temporary export permission remains active for 30 minutes.")
                        .build())
                .peerCohortProfile(CanonicalSecurityContext.PeerCohortProfile.builder()
                        .cohortId("FINANCE_ANALYST_APAC")
                        .summary("Peer cohort id: FINANCE_ANALYST_APAC | Cohort preferred resources: /api/customer/list | Outlier against cohort: true")
                        .preferredResources(List.of("/api/customer/list"))
                        .preferredActionFamilies(List.of("READ"))
                        .normalProtectableFrequencyBand("MEDIUM")
                        .normalSensitivityBand("MEDIUM")
                        .outlierAgainstCohort(true)
                        .build())
                .frictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                        .summary("Recent challenges: 2 | Recent blocks: 1 | Approval required: true | Approval status: PENDING | Approval lineage: Manager approved request-7, Director review pending | Recent denied access count: 1")
                        .recentChallengeCount(2)
                        .recentBlockCount(1)
                        .approvalRequired(true)
                        .approvalGranted(false)
                        .approvalStatus("PENDING")
                        .approvalLineage(List.of("Manager approved request-7", "Director review pending"))
                        .pendingApproverRoles(List.of("DIRECTOR"))
                        .approvalTicketId("APR-2026-0007")
                        .approvalDecisionAgeMinutes(12)
                        .recentDeniedAccessCount(1)
                        .build())
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .delegated(true)
                        .agentId("agent-1")
                        .objectiveFamily("THREAT_KNOWLEDGE_RUNTIME_REUSE")
                        .objectiveSummary("Contain export activity within threat knowledge runtime reuse scope")
                        .allowedOperations(List.of("READ"))
                        .approvalRequired(true)
                        .containmentOnly(true)
                        .objectiveDrift(true)
                        .objectiveDriftSummary("Current request diverges from delegated objective scope.")
                        .build())
                .reasoningMemoryProfile(CanonicalSecurityContext.ReasoningMemoryProfile.builder()
                        .summary("Reinforced cases: 6 | Hard negative cases: 1 | Recall priority: HIGH")
                        .reinforcedCaseCount(6L)
                        .hardNegativeCaseCount(1L)
                        .falseNegativeCaseCount(0L)
                        .knowledgeAssistedCaseCount(4L)
                        .objectiveAwareReasoningMemory("EXPORT_GUARD")
                        .retentionTier("HOT")
                        .recallPriority("HIGH")
                        .freshnessState("FRESH")
                        .reasoningState("READY")
                        .cohortPreference("TENANT_LOCAL")
                        .memoryRiskProfile("ELEVATED")
                        .retrievalWeight(87)
                        .matchedSignalKeys(List.of("signal-credential-export"))
                        .objectiveFamilies(List.of("EXPORT_GUARD", "DATA_EXFIL"))
                        .memoryGuardrails(List.of("Prefer TENANT_LOCAL memory weighting before weaker analogies."))
                        .xaiLinkedFacts(List.of("Customer export approval is usually required."))
                        .reasoningFacts(List.of("Recent export misuse cases were reinforced for this cohort."))
                        .crossTenantObjectiveMisusePackSummary("Cross-tenant signals: 2 | cross-tenant objective misuse evidence is available for EXPORT_GUARD, DATA_EXFIL")
                        .crossTenantObjectiveMisuseFacts(List.of("Signal signal-1 spans 4 tenants for objective families EXPORT_GUARD, DATA_EXFIL."))
                        .build())
                .bridge(CanonicalSecurityContext.Bridge.builder()
                        .coverageLevel("AUTHORIZATION_CONTEXT")
                        .coverageScore(80)
                        .summary("Bridge resolved authentication and authorization context for the current request.")
                        .remediationHints(List.of("If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored."))
                        .authenticationSource("SECURITY_CONTEXT")
                        .authorizationSource("HEADER")
                        .delegationSource("REQUEST_ATTRIBUTE")
                        .missingContexts(List.of("ORGANIZATION_CONTEXT"))
                        .build())
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of("Actor identity is available.", "Peer cohort delta is available."),
                        List.of("No cross-tenant objective memory is attached."),
                        List.of("Attach cross-tenant reasoning memory only when enterprise knowledge promotion is enabled."),
                        List.of("Reasoning memory is tenant-local; avoid claiming cross-tenant precedent."),
                        "Business-aware context is available for role, resource, and session reasoning."))
                .build();

        String promptSection = new PromptContextComposer().compose(context);

        assertThat(promptSection).contains("=== CONTEXT COVERAGE ===");
        assertThat(promptSection).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(promptSection).contains("=== IDENTITY AND ROLE CONTEXT ===");
        assertThat(promptSection).contains("=== AUTHENTICATION AND ASSURANCE CONTEXT ===");
        assertThat(promptSection).contains("=== RESOURCE AND ACTION CONTEXT ===");
        assertThat(promptSection).contains("=== SESSION NARRATIVE CONTEXT ===");
        assertThat(promptSection).contains("=== OBSERVED WORK PATTERN CONTEXT ===");
        assertThat(promptSection).contains("=== PERSONAL WORK PROFILE ===");
        assertThat(promptSection).contains("=== ROLE AND WORK SCOPE CONTEXT ===");
        assertThat(promptSection).contains("=== PEER COHORT DELTA ===");
        assertThat(promptSection).contains("=== FRICTION AND APPROVAL HISTORY ===");
        assertThat(promptSection).contains("=== DELEGATED OBJECTIVE CONTEXT ===");
        assertThat(promptSection).contains("=== OUTCOME AND REASONING MEMORY ===");
        assertThat(promptSection).contains("=== EXPLICIT MISSING KNOWLEDGE ===");
        assertThat(promptSection).contains("ExternalSubjectId: ext-alice");
        assertThat(promptSection).contains("BridgeSubjectKey: security_context:tenant-acme:ext-alice");
        assertThat(promptSection).contains("SessionAgeMinutes: 24");
        assertThat(promptSection).contains("PeerCohortId: FINANCE_ANALYST_APAC");
        assertThat(promptSection).contains("ReinforcedCaseCount: 6");
        assertThat(promptSection).contains("ConfidenceWarnings:");
        assertThat(promptSection).contains("BridgeAuthenticationSource: SECURITY_CONTEXT");
        assertThat(promptSection).contains("BridgeAuthorizationSource: HEADER");
        assertThat(promptSection).contains("BridgeCoverageSummary: Bridge resolved authentication and authorization context for the current request.");
        assertThat(promptSection).contains("BridgeRemediationHints: If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored.");
        assertThat(promptSection).contains("AuthenticationType: SESSION");
        assertThat(promptSection).contains("RecentMfaFailureCount: 2");
        assertThat(promptSection).contains("LastMfaUsedAt: 2026-03-24T08:58:00");
        assertThat(promptSection).contains("PolicyId: policy-1");
        assertThat(promptSection).contains("NormalReadWriteExportRatio: 80:15:5");
        assertThat(promptSection).contains("ProtectableResourceHeatmap: /api/customer/list=9, /api/customer/export=3");
        assertThat(promptSection).contains("SeasonalBusinessProfile: Quarter-end finance export review window");
        assertThat(promptSection).contains("LongTailLegitimateTasks: Quarter close export attestation");
        assertThat(promptSection).contains("NormalApprovalPatterns: Export requires manager approval");
        assertThat(promptSection).contains("ApprovalRequired: true");
        assertThat(promptSection).contains("CurrentResourceFamily: REPORT");
        assertThat(promptSection).contains("ResourceFamilyDrift: true");
        assertThat(promptSection).contains("TemporaryElevationReason: Emergency customer export review");
        assertThat(promptSection).contains("ApprovalLineage: Manager approved request-7, Director review pending");
        assertThat(promptSection).contains("ApprovalTicketId: APR-2026-0007");
        assertThat(promptSection).contains("Delegated: true");
        assertThat(promptSection).contains("ObjectiveDrift: true");
        assertThat(promptSection).contains("ObjectiveDriftSummary: Current request diverges from delegated objective scope.");
        assertThat(promptSection).contains("MatchedSignalKeys: signal-credential-export");
        assertThat(promptSection).contains("MemoryGuardrails: Prefer TENANT_LOCAL memory weighting before weaker analogies.");
        assertThat(promptSection).contains("CrossTenantObjectiveMisusePackSummary: Cross-tenant signals: 2 | cross-tenant objective misuse evidence is available for EXPORT_GUARD, DATA_EXFIL");
        assertThat(promptSection).contains("CrossTenantObjectiveMisuseFacts: Signal signal-1 spans 4 tenants for objective families EXPORT_GUARD, DATA_EXFIL.");
        assertThat(promptSection).contains("Customer Export Report");
        assertThat(promptSection).contains("CoverageLevel: BUSINESS_AWARE");
    }
}
