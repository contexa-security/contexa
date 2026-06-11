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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageLevel;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.model.ContextEvidenceRecord;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

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
                        .currentAccessHour(14)
                        .concurrentSessions(3)
                        .passwordAgeDays(9)
                        .build())
                .device(CanonicalSecurityContext.Device.builder()
                        .os("WINDOWS")
                        .osVersion("11")
                        .browser("Chrome")
                        .browserVersion("136")
                        .screenResolution("1920x1080")
                        .language("ko-KR")
                        .fingerprintMatch(true)
                        .build())
                .location(CanonicalSecurityContext.Location.builder()
                        .country("KR")
                        .city("Seoul")
                        .ipBand("203.0.113.0/24")
                        .asn("AS64512")
                        .build())
                .intent(CanonicalSecurityContext.Intent.builder()
                        .botUserAgent(false)
                        .missingReferer(true)
                        .languageMismatch(false)
                        .tlsFingerprintAltered(true)
                        .abnormalHeaderOrder(true)
                        .impossibleTravel(true)
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
                        .summary("Current resource is not present in the top observed work-history resources.")
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
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("PERSONAL_WORK_PROFILE")
                        .collectorId("PROTECTABLE_WORK_PROFILE_COLLECTOR")
                        .summary("Overall quality MODERATE | Observations 18 | Days covered 5")
                        .provenanceSummary("collector=PROTECTABLE_WORK_PROFILE_COLLECTOR,window=7d,observations=18,daysCovered=5")
                        .overallQualityGrade(ContextQualityGrade.MODERATE)
                        .overallQualityScore(68)
                        .scopeLimitations(List.of("Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself."))
                        .qualityWarnings(List.of("Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent."))
                        .fieldRecords(List.of(
                                ContextFieldTrustRecord.builder()
                                        .fieldPath("workProfile.frequentProtectableResources")
                                        .qualityGrade(ContextQualityGrade.STRONG)
                                        .observationCount(18)
                                        .daysCovered(5)
                                        .fallbackRate(0.0d)
                                        .unknownRate(0.0d)
                                        .provenanceSummary("observations=18,daysCovered=5,sources=requestPath")
                                        .build(),
                                ContextFieldTrustRecord.builder()
                                        .fieldPath("workProfile.frequentActionFamilies")
                                        .qualityGrade(ContextQualityGrade.WEAK)
                                        .observationCount(18)
                                        .daysCovered(5)
                                        .fallbackRate(0.33d)
                                        .unknownRate(0.0d)
                                        .provenanceSummary("observations=18,daysCovered=5,sources=actionFamily,httpMethod")
                                        .build()))
                        .evidenceRecords(List.of(ContextEvidenceRecord.builder()
                                .evidenceId("obs-1")
                                .summary("2026-03-24T09:00:00Z | ALLOWED | protectable | READ | /api/customer/list")
                                .build()))
                        .build()))
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .summary("Effective roles: ANALYST | Scope tags: customer_data | Current resource family: REPORT | Expected resource families: REPORT")
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
                        .summary("Peer cohort id: FINANCE_ANALYST_APAC | Cohort preferred resources: /api/customer/list")
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
                        .objectiveDriftSummary("Delegated objective comparison evidence is available. | Objective family: THREAT_KNOWLEDGE_RUNTIME_REUSE | Current action family: EXPORT | Current resource family: REPORT | Allowed action families: READ | Current action family is not listed in delegated action scope evidence.")
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

        assertThat(extractHeaders(promptSection)).containsExactly(
                "=== BRIDGE RESOLUTION CONTEXT ===",
                "=== CONTEXT COVERAGE ===",
                "=== IDENTITY AND ROLE CONTEXT ===",
                "=== AUTHENTICATION AND ASSURANCE CONTEXT ===",
                "=== DEVICE CONTEXT ===",
                "=== LOCATION CONTEXT ===",
                "=== REQUEST INTENT SIGNAL CONTEXT ===",
                "=== RESOURCE AND ACTION CONTEXT ===",
                "=== SESSION NARRATIVE CONTEXT ===",
                "=== OBSERVED WORK PATTERN CONTEXT ===",
                "=== PERSONAL WORK PROFILE ===",
                "=== ROLE AND WORK SCOPE CONTEXT ===",
                "=== PEER COHORT DELTA ===",
                "=== FRICTION AND APPROVAL HISTORY ===",
                "=== DELEGATED OBJECTIVE CONTEXT ===",
                "=== OUTCOME AND REASONING MEMORY ===",
                "=== EXPLICIT MISSING KNOWLEDGE ==="
        );
        assertThat(promptSection).contains("=== CONTEXT COVERAGE ===");
        assertThat(promptSection).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(promptSection).contains("=== IDENTITY AND ROLE CONTEXT ===");
        assertThat(promptSection).contains("=== AUTHENTICATION AND ASSURANCE CONTEXT ===");
        assertThat(promptSection).contains("=== DEVICE CONTEXT ===");
        assertThat(promptSection).contains("=== LOCATION CONTEXT ===");
        assertThat(promptSection).contains("=== REQUEST INTENT SIGNAL CONTEXT ===");
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
        assertThat(promptSection).contains("BridgeCompletenessSummary: Bridge resolved authentication and authorization context for the current request.");
        assertThat(promptSection).doesNotContain("BridgeCoverageScore:");
        assertThat(promptSection).contains("BridgeRemediationHints: If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored.");
        assertThat(promptSection).contains("AuthenticationType: SESSION");
        assertThat(promptSection).contains("RecentMfaFailureCount: 2");
        assertThat(promptSection).contains("LastMfaUsedAt: 2026-03-24T08:58:00");
        assertThat(promptSection).contains("CurrentAccessHour: 14");
        assertThat(promptSection).contains("ConcurrentSessions: 3");
        assertThat(promptSection).contains("PasswordAgeDays: 9");
        assertThat(promptSection).contains("DeviceOs: WINDOWS");
        assertThat(promptSection).contains("DeviceBrowser: Chrome");
        assertThat(promptSection).contains("Country: KR");
        assertThat(promptSection).contains("IpBand: 203.0.113.0/24");
        assertThat(promptSection).contains("MissingReferer: true");
        assertThat(promptSection).contains("ImpossibleTravel: true");
        assertThat(promptSection).contains("PolicyId: policy-1");
        assertThat(promptSection).contains("NormalReadWriteExportRatio: 80:15:5");
        assertThat(promptSection).contains("ProtectableResourceHeatmap: /api/customer/list=9, /api/customer/export=3");
        assertThat(promptSection).contains("WorkProfileEvidenceState: TRUSTED");
        assertThat(promptSection).contains("ContextEvidenceLimitation: PERSONAL_WORK_PROFILE | collector=PROTECTABLE_WORK_PROFILE_COLLECTOR");
        assertThat(promptSection).contains("ContextTrustLimitation: PERSONAL_WORK_PROFILE | Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself.");
        assertThat(promptSection).contains("ContextTrustWarning: PERSONAL_WORK_PROFILE | Action family baseline includes fallback-derived signals; do not treat action semantics as proof of user intent.");
        assertThat(promptSection).contains("ContextFieldCoverage: workProfile.frequentActionFamilies | observations=18 | days=5 | fallback=33% | unknown=0%");
        assertThat(promptSection).contains("ContextFieldLimitation: workProfile.frequentActionFamilies | value derivation depends on fallback signals");
        assertThat(promptSection).contains("SeasonalBusinessProfile: Quarter-end finance export review window");
        assertThat(promptSection).contains("LongTailLegitimateTasks: Quarter close export attestation");
        assertThat(promptSection).contains("NormalApprovalPatterns: Export requires manager approval");
        assertThat(promptSection).contains("ApprovalRequired: true");
        assertThat(promptSection).contains("CurrentResourceFamily: REPORT");
        assertThat(promptSection).contains("CurrentResourcePresentInObservedHistory: true");
        assertThat(promptSection).contains("RoleScopeDeltaCount: 0");
        assertThat(promptSection).contains("StrongestRoleScopeDelta: none");
        assertThat(promptSection).contains("RoleScopeDeltaSummary: no direct current-vs-scope mismatch detected");
        assertThat(promptSection).contains("CurrentResourceFamilyPresentInExpectedRoleScope: true");
        assertThat(promptSection).contains("CurrentActionFamilyPresentInExpectedRoleScope: true");
        assertThat(promptSection).contains("TemporaryElevationReason: Emergency customer export review");
        assertThat(promptSection).contains("ApprovalLineage: Manager approved request-7, Director review pending");
        assertThat(promptSection).contains("ApprovalTicketId: APR-2026-0007");
        assertThat(promptSection).contains("Delegated: true");
        assertThat(promptSection).contains("ObjectiveAlignmentEvidence: Delegated objective comparison evidence is available.");
        assertThat(promptSection).contains("CurrentResourcePresentInPeerPreferredResources: false");
        assertThat(promptSection).contains("CurrentActionFamilyPresentInPeerPreferredActions: true");
        assertThat(promptSection).contains("MatchedSignalKeys: signal-credential-export");
        assertThat(promptSection).contains("MemoryGuardrails: Prefer TENANT_LOCAL memory weighting before weaker analogies.");
        assertThat(promptSection).contains("CrossTenantObjectiveMisusePackSummary: Cross-tenant signals: 2 | cross-tenant objective misuse evidence is available for EXPORT_GUARD, DATA_EXFIL");
        assertThat(promptSection).contains("CrossTenantObjectiveMisuseFacts: Signal signal-1 spans 4 tenants for objective families EXPORT_GUARD, DATA_EXFIL.");
        assertThat(promptSection).contains("Customer Export Report");
        assertThat(promptSection).contains("CoverageLevel: BUSINESS_AWARE");
        assertThat(promptSection).doesNotContain("ResourceFamilyDrift:");
        assertThat(promptSection).doesNotContain("ActionFamilyDrift:");
        assertThat(promptSection).doesNotContain("ObjectiveDrift:");
        assertThat(promptSection).doesNotContain("OutlierAgainstCohort:");
        assertThat(promptSection).doesNotContain("ContextTrust: ");
    }

    @Test
    void composeShouldRenderDirectUserDelegationAsNotApplicable() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .delegated(false)
                        .objectiveDrift(false)
                        .objectiveDriftSummary("NOT_APPLICABLE: direct user request is not delegated.")
                        .build())
                .build();

        String promptSection = new PromptContextComposer().compose(context);

        assertThat(promptSection).contains("=== DELEGATED OBJECTIVE CONTEXT ===");
        assertThat(promptSection).contains("Delegated: false");
        assertThat(promptSection).contains("ObjectiveFamily: NOT_APPLICABLE");
        assertThat(promptSection).contains("ObjectiveSummary: NOT_APPLICABLE");
        assertThat(promptSection).contains("ObjectiveAlignmentEvidence: NOT_APPLICABLE: direct user request is not delegated.");
        assertThat(promptSection).doesNotContain("ObjectiveFamily: UNKNOWN");
        assertThat(promptSection).doesNotContain("ObjectiveSummary: UNKNOWN");
    }

    @Test
    void composeShouldMarkThinWorkProfileAsProvisional() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .workProfile(CanonicalSecurityContext.WorkProfile.builder()
                        .summary("Observed protectable resources /api/customer/list")
                        .frequentProtectableResources(List.of("/api/customer/list"))
                        .build())
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("PERSONAL_WORK_PROFILE")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .overallQualityScore(42)
                        .qualityWarnings(List.of("Work profile baseline is thin; treat pattern claims as provisional until more allowed observations accumulate."))
                        .build()))
                .build();

        String section = new PromptContextComposer().composeWorkProfileSection(context);

        assertThat(section).contains("=== PERSONAL WORK PROFILE ===");
        assertThat(section).contains("WorkProfileEvidenceState: PROVISIONAL");
        assertThat(section).contains("WorkProfileSummary: Observed protectable resources /api/customer/list");
    }

    @Test
    void composeBridgeSectionShouldRenderExplicitUnavailableState() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder().build();

        String section = new PromptContextComposer().composeBridgeSection(context);

        assertThat(section).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(section).contains("BridgeCompletenessLevel: UNAVAILABLE");
        assertThat(section).contains("BridgeCompletenessSummary: Bridge-derived identity and authorization context was not attached to this request.");
    }

    @Test
    void composeMissingKnowledgeSectionShouldKeepCriticalGapsWithoutCompactionMarkers() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .coverage(new ContextCoverageReport(
                        ContextCoverageLevel.BUSINESS_AWARE,
                        List.of("Actor identity is available."),
                        List.of("Bridge missing context: AUTHORIZATION_EFFECT."),
                        List.of(
                                "Populate an explicit authorization effect such as ALLOW or DENY for the current request.",
                                "Attach peer cohort deltas through enterprise cohort enrichment when available."),
                        List.of(
                                "Observed work pattern is missing; comparisons remain limited.",
                                "Personal work profile is missing; do not claim long-term normal work patterns.",
                                "Reasoning memory is missing; avoid assuming prior validated cases exist."),
                        "Business-aware context is available for role, resource, and session reasoning."))
                .contextTrustProfiles(List.of(ContextTrustProfile.builder()
                        .profileKey("ROLE_SCOPE_PROFILE")
                        .collectorId("ROLE_SCOPE_COLLECTOR")
                        .provenanceSummary("effectiveRoles=ADMIN,observations=0")
                        .overallQualityGrade(ContextQualityGrade.WEAK)
                        .scopeLimitations(List.of(
                                "Use this profile to understand role-scoped reach after authorization, not to infer business objective by itself.",
                                "Approval lineage still requires friction or enterprise memory context.",
                                "Delegated objective still requires explicit delegation context."))
                        .qualityWarnings(List.of(
                                "Role scope field expectedResourceFamilies has thin evidence.",
                                "Role scope field expectedActionFamilies has thin evidence.",
                                "Role scope field recentPermissionChanges has thin evidence.",
                                "Role scope baseline is thin; treat expected scope as provisional."))
                        .fieldRecords(List.of(
                                ContextFieldTrustRecord.builder()
                                        .fieldPath("roleScope.expectedResourceFamilies")
                                        .qualityGrade(ContextQualityGrade.WEAK)
                                        .observationCount(1)
                                        .daysCovered(0)
                                        .fallbackRate(0.0d)
                                        .unknownRate(1.0d)
                                        .provenanceSummary("Observations 0")
                                        .build(),
                                ContextFieldTrustRecord.builder()
                                        .fieldPath("roleScope.expectedActionFamilies")
                                        .qualityGrade(ContextQualityGrade.WEAK)
                                        .observationCount(1)
                                        .daysCovered(0)
                                        .fallbackRate(0.0d)
                                        .unknownRate(1.0d)
                                        .provenanceSummary("Observations 0")
                                        .build(),
                                ContextFieldTrustRecord.builder()
                                        .fieldPath("roleScope.recentPermissionChanges")
                                        .qualityGrade(ContextQualityGrade.WEAK)
                                        .observationCount(1)
                                        .daysCovered(0)
                                        .fallbackRate(0.0d)
                                        .unknownRate(1.0d)
                                        .provenanceSummary("Observed authorization-scope fingerprint changes")
                                        .build()))
                        .build()))
                .build();

        String section = new PromptContextComposer().composeMissingKnowledgeSection(context);

        assertThat(section).contains("=== EXPLICIT MISSING KNOWLEDGE ===");
        assertThat(section).contains("Bridge missing context: AUTHORIZATION_EFFECT.");
        assertThat(section).contains("ContextEvidenceLimitation: ROLE_SCOPE_PROFILE");
        assertThat(section).contains("ContextFieldCoverage: roleScope.expectedResourceFamilies");
        assertThat(section).contains("ContextFieldCoverage: roleScope.expectedActionFamilies");
        assertThat(section).doesNotContain("- Remediation:");
        assertThat(section).doesNotContain("- ConfidenceWarning:");
        assertThat(section).contains("roleScope.recentPermissionChanges");
        assertThat(section).doesNotContain("AdditionalContextTrustWarningsCompacted:");
    }

    @Test
    void composeShouldPreserveCriticalUnknownsWithDecisionLimitations() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .session(CanonicalSecurityContext.Session.builder()
                        .sessionId("session-unknowns")
                        .mfaVerified(false)
                        .build())
                .sessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile.builder()
                        .summary("Session continuity is not fully available.")
                        .build())
                .build();

        String promptSection = new PromptContextComposer().compose(context);

        assertThat(promptSection).contains("=== REQUEST INTENT SIGNAL CONTEXT ===");
        assertThat(promptSection).contains("FailedLoginAttempts: UNKNOWN - not available from authentication context");
        assertThat(promptSection).contains("NewDevice: UNKNOWN - not available from device context");
        assertThat(promptSection).contains("NewSession: UNKNOWN - not available from session context");
        assertThat(promptSection).contains("NewUser: UNKNOWN - not available from identity context");
        assertThat(promptSection).contains("PreviousPath: UNKNOWN - not available from session narrative context");
        assertThat(promptSection).contains("BotUserAgent: UNKNOWN - not available from intent signal context");
    }

    @Test
    void composeShouldExplainRoleApprovalAndDelegationUnknowns() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentResourceFamily("REPORT")
                        .currentActionFamily("READ")
                        .summary("Role scope evidence is not mature.")
                        .build())
                .frictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                        .summary("Approval provider did not provide lineage.")
                        .build())
                .delegation(CanonicalSecurityContext.Delegation.builder()
                        .delegated(true)
                        .build())
                .build();

        String promptSection = new PromptContextComposer().compose(context);

        assertThat(promptSection)
                .contains("RecentPermissionChanges: UNKNOWN - recent permission change evidence was not provided; do not infer permission stability.")
                .contains("CurrentResourceFamilyPresentInExpectedRoleScope: UNKNOWN - comparison baseline is unavailable; do not treat this scope comparison as proof.")
                .contains("CurrentActionFamilyPresentInExpectedRoleScope: UNKNOWN - comparison baseline is unavailable; do not treat this scope comparison as proof.")
                .contains("ApprovalRequired: UNKNOWN - approval provider supplied no approval requirement for this request; do not infer prior approval.")
                .contains("ApprovalGranted: UNKNOWN - approval provider supplied no grant result for this request; do not infer granted approval.")
                .contains("ApprovalStatus: UNKNOWN - approval provider supplied no approval lineage for this request; do not infer prior approval.")
                .contains("ObjectiveAlignmentEvidence: UNKNOWN - delegation context supplied no objective alignment evidence; do not infer business intent.");
    }

    private List<String> extractHeaders(String promptSection) {
        List<String> headers = new ArrayList<>();
        for (String line : promptSection.split("\\R")) {
            if (line.startsWith("=== ") && line.endsWith(" ===")) {
                headers.add(line);
            }
        }
        return headers;
    }
}
