package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultCanonicalSecurityContextProviderTest {

    @Test
    void resolveShouldNormalizeEventMetadataIntoCanonicalSecurityContext() {
        InMemoryResourceContextRegistry registry = new InMemoryResourceContextRegistry();
        registry.register(new ResourceContextDescriptor(
                "/api/customer/export",
                "REPORT",
                "Customer Export Report",
                "HIGH",
                List.of("ANALYST"),
                List.of("READ", "EXPORT"),
                true,
                true));

        DefaultCanonicalSecurityContextProvider provider =
                new DefaultCanonicalSecurityContextProvider(registry, new ContextCoverageEvaluator());

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .userAgent("Mozilla/5.0")
                .timestamp(LocalDateTime.of(2026, 3, 23, 14, 0))
                .build();
        event.addMetadata("requestPath", "/api/customer/export");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("externalSubjectId", "ext-alice");
        event.addMetadata("tenantId", "tenant-acme");
        event.addMetadata("organizationId", "tenant-acme");
        event.addMetadata("department", "finance");
        event.addMetadata("position", "Senior Analyst");
        event.addMetadata("bridgeSubjectKey", "security_context:tenant-acme:ext-alice");
        event.addMetadata("userRoles", "ANALYST,EXPORT_REVIEWER");
        event.addMetadata("effectivePermissions", List.of("report.read", "report.export"));
        event.addMetadata("scopeTags", List.of("customer_data", "export"));
        event.addMetadata("policyId", "policy-1");
        event.addMetadata("policyVersion", "2026.03");
        event.addMetadata("authenticationType", "SESSION");
        event.addMetadata("authenticationAssurance", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("recentMfaFailureCount", 2);
        event.addMetadata("lastMfaUsedAt", "2026-03-24T08:58:00");
        event.addMetadata("failedLoginAttempts", 1);
        event.addMetadata("recentRequestCount", 7);
        event.addMetadata("recentChallengeCount", 2);
        event.addMetadata("recentBlockCount", 1);
        event.addMetadata("sessionAgeMinutes", 24);
        event.addMetadata("previousPath", "/api/customer/list");
        event.addMetadata("previousActionFamily", "READ");
        event.addMetadata("lastRequestIntervalMs", 800L);
        event.addMetadata("sessionActionSequence", List.of("READ", "READ", "EXPORT"));
        event.addMetadata("sessionProtectableSequence", List.of("/api/customer/list", "/api/customer/export"));
        event.addMetadata("burstPattern", false);
        event.addMetadata("normalAccessHours", List.of(9, 10, 11));
        event.addMetadata("normalAccessDays", List.of(1, 2, 3, 4, 5));
        event.addMetadata("normalRequestRate", 2.5d);
        event.addMetadata("protectableResourceHeatmap", List.of("/api/customer/list=9", "/api/customer/export=3"));
        event.addMetadata("seasonalBusinessProfile", "Quarter-end finance export review window");
        event.addMetadata("longTailLegitimateTasks", List.of("Quarter close export attestation"));
        event.addMetadata("normalReadWriteExportRatio", "80:15:5");
        event.addMetadata("protectableResourceHeatmap", List.of("/api/customer/list=9", "/api/customer/export=3"));
        event.addMetadata("seasonalBusinessProfile", "Quarter-end finance export review window");
        event.addMetadata("longTailLegitimateTasks", List.of("Quarter close export attestation"));
        event.addMetadata("expectedResourceFamilies", List.of("REPORT", "CUSTOMER_DATA"));
        event.addMetadata("expectedActionFamilies", List.of("READ", "EXPORT"));
        event.addMetadata("currentResourceFamily", "REPORT");
        event.addMetadata("currentActionFamily", "EXPORT");
        event.addMetadata("resourceFamilyDrift", false);
        event.addMetadata("actionFamilyDrift", false);
        event.addMetadata("normalApprovalPatterns", List.of("Export requires manager approval"));
        event.addMetadata("recentPermissionChanges", List.of("Temporary export permission granted yesterday"));
        event.addMetadata("temporaryElevation", true);
        event.addMetadata("temporaryElevationReason", "Emergency customer export review");
        event.addMetadata("elevationWindowSummary", "Temporary export permission remains active for 30 minutes.");
        event.addMetadata("approvalRequired", true);
        event.addMetadata("approvalStatus", "PENDING");
        event.addMetadata("approvalLineage", List.of("Manager approved request-7", "Director review pending"));
        event.addMetadata("pendingApproverRoles", List.of("DIRECTOR"));
        event.addMetadata("approvalTicketId", "APR-2026-0007");
        event.addMetadata("approvalDecisionAgeMinutes", 12);
        event.addMetadata("breakGlass", false);
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageScore", 80);
        event.addMetadata("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request.");
        event.addMetadata("bridgeRemediationHints", List.of("If delegated agents are used, propagate delegation metadata for the current request. Otherwise this gap can be ignored."));
        event.addMetadata("bridgeMissingContexts", List.of("DELEGATION"));
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("agentId", "agent-7");
        event.addMetadata("objectiveId", "objective-export-review");
        event.addMetadata("objectiveFamily", "EXPORT_GUARD");
        event.addMetadata("objectiveSummary", "Review and export approved customer reports only");
        event.addMetadata("allowedOperations", List.of("READ"));
        event.addMetadata("allowedResources", List.of("/api/customer/list"));
        event.addMetadata("peerCohortId", "FINANCE_ANALYST_APAC");
        event.addMetadata("cohortPreferredResources", List.of("/api/customer/list", "/api/customer/search"));
        event.addMetadata("cohortPreferredActionFamilies", List.of("READ", "EXPORT"));
        event.addMetadata("cohortNormalProtectableFrequencyBand", "MEDIUM");
        event.addMetadata("cohortNormalSensitivityBand", "MEDIUM");
        event.addMetadata("outlierAgainstCohort", true);
        event.addMetadata("reinforcedCaseCount", 6L);
        event.addMetadata("hardNegativeCaseCount", 1L);
        event.addMetadata("knowledgeAssistedCaseCount", 4L);
        event.addMetadata("objectiveAwareReasoningMemory", "EXPORT_GUARD");
        event.addMetadata("retentionTier", "HOT");
        event.addMetadata("recallPriority", "HIGH");
        event.addMetadata("freshnessState", "FRESH");
        event.addMetadata("reasoningState", "READY");
        event.addMetadata("cohortPreference", "TENANT_LOCAL");
        event.addMetadata("memoryRiskProfile", "ELEVATED");
        event.addMetadata("retrievalWeight", 87);
        event.addMetadata("matchedSignalKeys", List.of("signal-credential-export"));
        event.addMetadata("memoryGuardrails", List.of("Prefer tenant-local memory before analogical matches."));
        event.addMetadata("objectiveFamilies", List.of("EXPORT_GUARD", "DATA_EXFIL"));
        event.addMetadata("xaiLinkedFacts", List.of("Customer export approval is usually required."));
        event.addMetadata("reasoningFacts", List.of("Recent export misuse cases were reinforced for this cohort."));
        event.addMetadata("crossTenantObjectiveMisusePackSummary", "Cross-tenant signals: 2 | cross-tenant objective misuse evidence is available for EXPORT_GUARD, DATA_EXFIL");
        event.addMetadata("crossTenantObjectiveMisuseFacts", List.of("Signal signal-1 spans 4 tenants for objective families EXPORT_GUARD, DATA_EXFIL."));

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getActor().getUserId()).isEqualTo("alice");
        assertThat(context.getActor().getExternalSubjectId()).isEqualTo("ext-alice");
        assertThat(context.getActor().getOrganizationId()).isEqualTo("tenant-acme");
        assertThat(context.getActor().getTenantId()).isEqualTo("tenant-acme");
        assertThat(context.getActor().getPosition()).isEqualTo("Senior Analyst");
        assertThat(context.getActor().getBridgeSubjectKey()).isEqualTo("security_context:tenant-acme:ext-alice");
        assertThat(context.getAuthorization().getEffectiveRoles()).contains("ANALYST", "EXPORT_REVIEWER");
        assertThat(context.getAuthorization().getEffectivePermissions()).contains("report.read", "report.export");
        assertThat(context.getAuthorization().getPolicyId()).isEqualTo("policy-1");
        assertThat(context.getAuthorization().getPolicyVersion()).isEqualTo("2026.03");
        assertThat(context.getSession().getAuthenticationType()).isEqualTo("SESSION");
        assertThat(context.getSession().getAuthenticationAssurance()).isEqualTo("HIGH");
        assertThat(context.getSession().getRecentMfaFailureCount()).isEqualTo(2);
        assertThat(context.getSession().getLastMfaUsedAt()).isEqualTo("2026-03-24T08:58:00");
        assertThat(context.getSession().getRecentChallengeCount()).isEqualTo(2);
        assertThat(context.getSession().getRecentBlockCount()).isEqualTo(1);
        assertThat(context.getSessionNarrativeProfile()).isNotNull();
        assertThat(context.getSessionNarrativeProfile().getSessionAgeMinutes()).isEqualTo(24);
        assertThat(context.getSessionNarrativeProfile().getPreviousPath()).isEqualTo("/api/customer/list");
        assertThat(context.getSessionNarrativeProfile().getSessionActionSequence()).contains("READ", "EXPORT");
        assertThat(context.getResource().getBusinessLabel()).isEqualTo("Customer Export Report");
        assertThat(context.getResource().getSensitivity()).isEqualTo("HIGH");
        assertThat(context.getWorkProfile()).isNotNull();
        assertThat(context.getWorkProfile().getNormalAccessHours()).containsExactly(9, 10, 11);
        assertThat(context.getWorkProfile().getProtectableResourceHeatmap()).contains("/api/customer/list=9", "/api/customer/export=3");
        assertThat(context.getWorkProfile().getSeasonalBusinessProfile()).isEqualTo("Quarter-end finance export review window");
        assertThat(context.getWorkProfile().getLongTailLegitimateTasks()).contains("Quarter close export attestation");
        assertThat(context.getRoleScopeProfile()).isNotNull();
        assertThat(context.getRoleScopeProfile().getExpectedResourceFamilies()).contains("REPORT", "CUSTOMER_DATA");
        assertThat(context.getRoleScopeProfile().getCurrentResourceFamily()).isEqualTo("REPORT");
        assertThat(context.getRoleScopeProfile().getCurrentActionFamily()).isEqualTo("EXPORT");
        assertThat(context.getRoleScopeProfile().getTemporaryElevation()).isTrue();
        assertThat(context.getRoleScopeProfile().getTemporaryElevationReason()).isEqualTo("Emergency customer export review");
        assertThat(context.getPeerCohortProfile()).isNotNull();
        assertThat(context.getPeerCohortProfile().getCohortId()).isEqualTo("FINANCE_ANALYST_APAC");
        assertThat(context.getPeerCohortProfile().getOutlierAgainstCohort()).isTrue();
        assertThat(context.getFrictionProfile()).isNotNull();
        assertThat(context.getFrictionProfile().getApprovalRequired()).isTrue();
        assertThat(context.getFrictionProfile().getApprovalStatus()).isEqualTo("PENDING");
        assertThat(context.getFrictionProfile().getApprovalLineage()).contains("Manager approved request-7", "Director review pending");
        assertThat(context.getFrictionProfile().getApprovalTicketId()).isEqualTo("APR-2026-0007");
        assertThat(context.getDelegation()).isNotNull();
        assertThat(context.getDelegation().getDelegated()).isTrue();
        assertThat(context.getDelegation().getObjectiveDrift()).isTrue();
        assertThat(context.getDelegation().getObjectiveDriftSummary()).contains("diverges from delegated objective scope");
        assertThat(context.getDelegation().getObjectiveDriftSummary()).contains("Current action family: EXPORT");
        assertThat(context.getDelegation().getObjectiveDriftSummary()).contains("Current resource family: REPORT");
        assertThat(context.getCoverage().confidenceWarnings())
                .anyMatch(value -> value.contains("Delegated objective drift is present"));
        assertThat(context.getReasoningMemoryProfile()).isNotNull();
        assertThat(context.getReasoningMemoryProfile().getReinforcedCaseCount()).isEqualTo(6L);
        assertThat(context.getReasoningMemoryProfile().getObjectiveAwareReasoningMemory()).isEqualTo("EXPORT_GUARD");
        assertThat(context.getReasoningMemoryProfile().getMatchedSignalKeys()).contains("signal-credential-export");
        assertThat(context.getReasoningMemoryProfile().getMemoryGuardrails()).contains("Prefer tenant-local memory before analogical matches.");
        assertThat(context.getReasoningMemoryProfile().getCrossTenantObjectiveMisusePackSummary())
                .contains("cross-tenant objective misuse evidence");
        assertThat(context.getReasoningMemoryProfile().getCrossTenantObjectiveMisuseFacts())
                .contains("Signal signal-1 spans 4 tenants for objective families EXPORT_GUARD, DATA_EXFIL.");
        assertThat(context.getBridge()).isNotNull();
        assertThat(context.getBridge().getCoverageLevel()).isEqualTo("AUTHORIZATION_CONTEXT");
        assertThat(context.getBridge().getSummary()).contains("authentication and authorization context");
        assertThat(context.getBridge().getRemediationHints()).hasSize(1);
        assertThat(context.getBridge().getAuthenticationSource()).isEqualTo("SECURITY_CONTEXT");
        assertThat(context.getBridge().getAuthorizationSource()).isEqualTo("HEADER");
        assertThat(context.getBridge().getMissingContexts()).contains("DELEGATION");
        assertThat(context.getCoverage().level()).isEqualTo(ContextCoverageLevel.BUSINESS_AWARE);
    }

    @Test
    void resolveShouldApplyExternalProvidersAndObservedScopeInference() {
        DefaultCanonicalSecurityContextProvider provider = new DefaultCanonicalSecurityContextProvider(
                new InMemoryResourceContextRegistry(),
                new ContextCoverageEvaluator(),
                List.<AuthenticationContextProvider>of((event, context) -> {
                    if (context.getActor() == null) {
                        context.setActor(new CanonicalSecurityContext.Actor());
                    }
                    context.getActor().setPrincipalType("EXTERNAL_WORKFORCE");
                }),
                List.<AuthorizationSnapshotProvider>of((event, context) -> {
                    if (context.getAuthorization() == null) {
                        context.setAuthorization(new CanonicalSecurityContext.Authorization());
                    }
                    context.getAuthorization().setScopeTags(List.of("finance_ops", "export"));
                }),
                List.<OrganizationContextProvider>of((event, context) -> {
                    if (context.getActor() == null) {
                        context.setActor(new CanonicalSecurityContext.Actor());
                    }
                    context.getActor().setDepartment("finance");
                }),
                List.of(),
                new MetadataObservedScopeInferenceService());

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .build();
        event.addMetadata("requestPath", "/api/customer/export");
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("authenticationType", "SESSION");
        event.addMetadata("authenticationAssurance", "HIGH");
        event.addMetadata("recentChallengeCount", 2);
        event.addMetadata("recentBlockCount", 1);
        event.addMetadata("sessionAgeMinutes", 18);
        event.addMetadata("previousPath", "/api/customer/list");
        event.addMetadata("normalAccessHours", List.of(9, 10, 11));
        event.addMetadata("normalRequestRate", 2.5d);
        event.addMetadata("protectableResourceHeatmap", List.of("/api/customer/list=9", "/api/customer/export=3"));
        event.addMetadata("seasonalBusinessProfile", "Quarter-end finance export review window");
        event.addMetadata("longTailLegitimateTasks", List.of("Quarter close export attestation"));
        event.addMetadata("expectedResourceFamilies", List.of("REPORT"));
        event.addMetadata("normalApprovalPatterns", List.of("Export requires manager approval"));
        event.addMetadata("approvalRequired", true);
        event.addMetadata("approvalStatus", "PENDING");
        event.addMetadata("peerCohortId", "FINANCE_ANALYST_APAC");
        event.addMetadata("cohortPreferredActionFamilies", List.of("READ"));
        event.addMetadata("reinforcedCaseCount", 2L);
        event.addMetadata("retentionTier", "WARM");
        event.addMetadata("protectableAccessHistory", List.of(
                java.util.Map.of("resourceId", "/api/customer/list", "actionFamily", "READ", "result", "ALLOWED"),
                java.util.Map.of("resourceId", "/api/customer/list", "actionFamily", "READ", "result", "ALLOWED"),
                java.util.Map.of("resourceId", "/api/customer/export", "actionFamily", "EXPORT", "result", "DENIED", "isSensitiveResource", true)));

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getActor().getPrincipalType()).isEqualTo("EXTERNAL_WORKFORCE");
        assertThat(context.getActor().getDepartment()).isEqualTo("finance");
        assertThat(context.getAuthorization().getScopeTags()).contains("finance_ops", "export");
        assertThat(context.getObservedScope()).isNotNull();
        assertThat(context.getObservedScope().getFrequentResources()).contains("/api/customer/list");
        assertThat(context.getObservedScope().getRecentDeniedAccessCount()).isEqualTo(1);
        assertThat(context.getSessionNarrativeProfile()).isNotNull();
        assertThat(context.getSessionNarrativeProfile().getSessionAgeMinutes()).isEqualTo(18);
        assertThat(context.getWorkProfile()).isNotNull();
        assertThat(context.getWorkProfile().getNormalAccessHours()).containsExactly(9, 10, 11);
        assertThat(context.getWorkProfile().getProtectableResourceHeatmap()).contains("/api/customer/list=9", "/api/customer/export=3");
        assertThat(context.getWorkProfile().getSeasonalBusinessProfile()).isEqualTo("Quarter-end finance export review window");
        assertThat(context.getWorkProfile().getLongTailLegitimateTasks()).contains("Quarter close export attestation");
        assertThat(context.getRoleScopeProfile()).isNotNull();
        assertThat(context.getRoleScopeProfile().getExpectedResourceFamilies()).contains("REPORT");
        assertThat(context.getPeerCohortProfile()).isNotNull();
        assertThat(context.getPeerCohortProfile().getCohortId()).isEqualTo("FINANCE_ANALYST_APAC");
        assertThat(context.getFrictionProfile()).isNotNull();
        assertThat(context.getFrictionProfile().getApprovalRequired()).isTrue();
        assertThat(context.getFrictionProfile().getRecentDeniedAccessCount()).isEqualTo(1);
        assertThat(context.getReasoningMemoryProfile()).isNotNull();
        assertThat(context.getReasoningMemoryProfile().getRetentionTier()).isEqualTo("WARM");
    }

    @Test
    void resolveShouldApplyCanonicalHardeningAfterProviderContribution() {
        DefaultCanonicalSecurityContextProvider provider = new DefaultCanonicalSecurityContextProvider(
                new InMemoryResourceContextRegistry(),
                new ContextCoverageEvaluator(),
                List.<AuthenticationContextProvider>of((event, context) -> {
                    if (context.getActor() == null) {
                        context.setActor(new CanonicalSecurityContext.Actor());
                    }
                    context.getActor().setPrincipalType(" employee ");
                    context.getActor().setRoleSet(List.of("ANALYST", " ANALYST ", ""));
                }),
                List.<AuthorizationSnapshotProvider>of((event, context) -> {
                    if (context.getAuthorization() == null) {
                        context.setAuthorization(new CanonicalSecurityContext.Authorization());
                    }
                    context.getAuthorization().setScopeTags(List.of(" finance_ops ", "", "finance_ops"));
                }),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                new MetadataObservedScopeInferenceService(),
                new CanonicalSecurityContextHardener());

        SecurityEvent event = SecurityEvent.builder()
                .userId(" alice ")
                .sessionId(" session-1 ")
                .build();
        event.addMetadata("requestPath", " /api/customer/export ");

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getActor().getUserId()).isEqualTo("alice");
        assertThat(context.getActor().getPrincipalType()).isEqualTo("EMPLOYEE");
        assertThat(context.getActor().getRoleSet()).containsExactly("ANALYST");
        assertThat(context.getAuthorization().getScopeTags()).containsExactly("finance_ops");
        assertThat(context.getSession().getSessionId()).isEqualTo("session-1");
        assertThat(context.getResource().getResourceId()).isEqualTo("/api/customer/export");
    }

    @Test
    void resolveShouldPopulateSessionNarrativeFromCollectorWithoutSyntheticMetadata() {
        SessionNarrativeCollector collector =
                new DefaultSessionNarrativeCollector(new io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore());
        DefaultCanonicalSecurityContextProvider provider =
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator(),
                        collector);

        SecurityEvent first = SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .timestamp(LocalDateTime.of(2026, 3, 25, 10, 0, 0))
                .build();
        first.addMetadata("requestPath", "/api/customer/list");
        first.addMetadata("httpMethod", "GET");
        first.addMetadata("actionFamily", "READ");
        first.addMetadata("isProtectable", true);

        SecurityEvent second = SecurityEvent.builder()
                .userId("alice")
                .sessionId("session-1")
                .timestamp(LocalDateTime.of(2026, 3, 25, 10, 0, 0, 800_000_000))
                .build();
        second.addMetadata("requestPath", "/api/customer/export");
        second.addMetadata("httpMethod", "POST");
        second.addMetadata("actionFamily", "EXPORT");
        second.addMetadata("isProtectable", true);

        provider.resolve(first);
        CanonicalSecurityContext context = provider.resolve(second).orElseThrow();

        assertThat(context.getSessionNarrativeProfile()).isNotNull();
        assertThat(context.getSessionNarrativeProfile().getPreviousPath()).isEqualTo("/api/customer/list");
        assertThat(context.getSessionNarrativeProfile().getPreviousActionFamily()).isEqualTo("READ");
        assertThat(context.getSessionNarrativeProfile().getLastRequestIntervalMs()).isEqualTo(800L);
        assertThat(context.getSessionNarrativeProfile().getSessionActionSequence())
                .containsExactly("READ", "EXPORT");
        assertThat(context.getSessionNarrativeProfile().getSessionProtectableSequence())
                .containsExactly("/api/customer/list", "/api/customer/export");
        assertThat(second.getMetadata()).containsKeys(
                "sessionNarrativeSummary",
                "sessionAgeMinutes",
                "previousPath",
                "previousActionFamily",
                "lastRequestIntervalMs",
                "sessionActionSequence",
                "sessionProtectableSequence",
                "burstPattern");
    }

    @Test
    void resolveShouldPopulateWorkProfileFromCollectorWithoutSyntheticMetadata() {
        ProtectableWorkProfileCollector collector =
                new DefaultProtectableWorkProfileCollector(new io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore());
        DefaultCanonicalSecurityContextProvider provider =
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator(),
                        collector);

        SecurityEvent first = SecurityEvent.builder()
                .userId("alice")
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0, 0))
                .build();
        first.addMetadata("tenantId", "tenant-acme");
        first.addMetadata("requestPath", "/api/customer/list");
        first.addMetadata("httpMethod", "GET");
        first.addMetadata("actionFamily", "READ");
        first.addMetadata("currentResourceFamily", "REPORT");
        first.addMetadata("resourceSensitivity", "HIGH");
        first.addMetadata("isProtectable", true);
        first.addMetadata("granted", true);

        SecurityEvent second = SecurityEvent.builder()
                .userId("alice")
                .timestamp(LocalDateTime.of(2026, 3, 25, 10, 0, 0))
                .build();
        second.addMetadata("tenantId", "tenant-acme");
        second.addMetadata("requestPath", "/api/customer/export");
        second.addMetadata("httpMethod", "POST");
        second.addMetadata("actionFamily", "EXPORT");
        second.addMetadata("currentResourceFamily", "REPORT");
        second.addMetadata("resourceSensitivity", "HIGH");
        second.addMetadata("isProtectable", true);
        second.addMetadata("granted", true);

        provider.resolve(first);
        CanonicalSecurityContext context = provider.resolve(second).orElseThrow();

        assertThat(context.getWorkProfile()).isNotNull();
        assertThat(context.getWorkProfile().getFrequentProtectableResources()).containsExactly("/api/customer/list");
        assertThat(context.getWorkProfile().getFrequentActionFamilies()).containsExactly("READ");
        assertThat(context.getWorkProfile().getNormalAccessHours()).containsExactly(9);
        assertThat(context.getWorkProfile().getNormalAccessDays())
                .containsExactly(LocalDateTime.of(2026, 3, 25, 9, 0).getDayOfWeek().getValue());
        assertThat(context.getWorkProfile().getNormalRequestRate()).isEqualTo(1.0d);
        assertThat(context.getWorkProfile().getProtectableInvocationDensity()).isEqualTo(1.0d);
        assertThat(context.getWorkProfile().getProtectableResourceHeatmap()).containsExactly("/api/customer/list=1");
        assertThat(context.getWorkProfile().getNormalReadWriteExportRatio()).isEqualTo("100:0:0");
        assertThat(context.getContextTrustProfiles()).hasSize(1);
        assertThat(context.getContextTrustProfiles().get(0).getProfileKey()).isEqualTo("PERSONAL_WORK_PROFILE");
        assertThat(context.getContextTrustProfiles().get(0).getFieldRecords())
                .extracting(ContextFieldTrustRecord::getFieldPath)
                .contains("workProfile.frequentProtectableResources", "workProfile.frequentActionFamilies");
        assertThat(second.getMetadata()).containsKeys(
                "workProfileSummary",
                "frequentProtectableResources",
                "frequentActionFamilies",
                "normalAccessHours",
                "normalAccessDays",
                "normalRequestRate",
                "protectableInvocationDensity",
                "protectableResourceHeatmap",
                "frequentSensitiveResourceCategories",
                "normalReadWriteExportRatio",
                "workProfileTrustProfile",
                "workProfileQualityGrade",
                "workProfileQualityScore",
                "workProfileProvenanceSummary");
    }

    @Test
    void resolveShouldPreservePeerFrictionAndReasoningProfilesFromProviders() {
        DefaultCanonicalSecurityContextProvider provider = new DefaultCanonicalSecurityContextProvider(
                new InMemoryResourceContextRegistry(),
                new ContextCoverageEvaluator(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of((event, context) -> context.setPeerCohortProfile(CanonicalSecurityContext.PeerCohortProfile.builder()
                        .cohortId("FINANCE_COHORT")
                        .preferredResources(List.of("/api/customer/export"))
                        .outlierAgainstCohort(true)
                        .build())),
                List.of((event, context) -> context.setFrictionProfile(CanonicalSecurityContext.FrictionProfile.builder()
                        .approvalRequired(true)
                        .approvalStatus("PENDING")
                        .approvalLineage(List.of("Manager review pending"))
                        .approvalTicketId("APR-2026-0042")
                        .build())),
                List.of((event, context) -> context.setReasoningMemoryProfile(CanonicalSecurityContext.ReasoningMemoryProfile.builder()
                        .retentionTier("HOT")
                        .matchedSignalKeys(List.of("signal-credential-export"))
                        .memoryGuardrails(List.of("Prefer tenant-local memory weighting before weaker analogies."))
                        .build())),
                new MetadataObservedScopeInferenceService(),
                new CanonicalSecurityContextHardener());

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .build();
        event.addMetadata("requestPath", "/api/customer/export");
        event.addMetadata("httpMethod", "GET");

        CanonicalSecurityContext context = provider.resolve(event).orElseThrow();

        assertThat(context.getPeerCohortProfile()).isNotNull();
        assertThat(context.getPeerCohortProfile().getCohortId()).isEqualTo("FINANCE_COHORT");
        assertThat(context.getPeerCohortProfile().getPreferredResources()).contains("/api/customer/export");
        assertThat(context.getFrictionProfile()).isNotNull();
        assertThat(context.getFrictionProfile().getApprovalStatus()).isEqualTo("PENDING");
        assertThat(context.getFrictionProfile().getApprovalLineage()).contains("Manager review pending");
        assertThat(context.getFrictionProfile().getApprovalTicketId()).isEqualTo("APR-2026-0042");
        assertThat(context.getReasoningMemoryProfile()).isNotNull();
        assertThat(context.getReasoningMemoryProfile().getRetentionTier()).isEqualTo("HOT");
        assertThat(context.getReasoningMemoryProfile().getMatchedSignalKeys()).contains("signal-credential-export");
        assertThat(context.getReasoningMemoryProfile().getMemoryGuardrails())
                .contains("Prefer tenant-local memory weighting before weaker analogies.");
    }
}
