package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.springframework.util.StringUtils;

import java.util.*;

public class DefaultCanonicalSecurityContextProvider implements CanonicalSecurityContextProvider {

    private final ResourceContextRegistry resourceContextRegistry;
    private final ContextCoverageEvaluator coverageEvaluator;
    private final List<AuthenticationContextProvider> authenticationContextProviders;
    private final List<AuthorizationSnapshotProvider> authorizationSnapshotProviders;
    private final List<OrganizationContextProvider> organizationContextProviders;
    private final List<DelegationContextProvider> delegationContextProviders;
    private final List<PeerCohortContextProvider> peerCohortContextProviders;
    private final List<FrictionContextProvider> frictionContextProviders;
    private final List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders;
    private final ObservedScopeInferenceService observedScopeInferenceService;
    private final SessionNarrativeCollector sessionNarrativeCollector;
    private final ProtectableWorkProfileCollector protectableWorkProfileCollector;
    private final RoleScopeCollector roleScopeCollector;
    private final CanonicalSecurityContextHardener contextHardener;
    private final ObjectiveDriftEvaluator objectiveDriftEvaluator = new ObjectiveDriftEvaluator();

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator) {
        this(resourceContextRegistry, coverageEvaluator, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                new MetadataObservedScopeInferenceService(), null, null, null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            RoleScopeCollector roleScopeCollector) {
        this(resourceContextRegistry, coverageEvaluator, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                new MetadataObservedScopeInferenceService(), null, null, roleScopeCollector, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            SessionNarrativeCollector sessionNarrativeCollector) {
        this(resourceContextRegistry, coverageEvaluator, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                new MetadataObservedScopeInferenceService(), sessionNarrativeCollector, null, null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            ProtectableWorkProfileCollector protectableWorkProfileCollector) {
        this(resourceContextRegistry, coverageEvaluator, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                new MetadataObservedScopeInferenceService(), null, protectableWorkProfileCollector, null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            SessionNarrativeCollector sessionNarrativeCollector,
            ProtectableWorkProfileCollector protectableWorkProfileCollector) {
        this(resourceContextRegistry, coverageEvaluator, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                new MetadataObservedScopeInferenceService(), sessionNarrativeCollector, protectableWorkProfileCollector, null,
                new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, List.of(), List.of(), List.of(),
                observedScopeInferenceService, null, null, null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<FrictionContextProvider> frictionContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, frictionContextProviders,
                reasoningMemoryContextProviders, observedScopeInferenceService, null, null, null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<FrictionContextProvider> frictionContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            SessionNarrativeCollector sessionNarrativeCollector) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, frictionContextProviders,
                reasoningMemoryContextProviders, observedScopeInferenceService, sessionNarrativeCollector, null, null,
                new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<FrictionContextProvider> frictionContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            SessionNarrativeCollector sessionNarrativeCollector,
            ProtectableWorkProfileCollector protectableWorkProfileCollector) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, frictionContextProviders,
                reasoningMemoryContextProviders, observedScopeInferenceService, sessionNarrativeCollector, protectableWorkProfileCollector,
                null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<FrictionContextProvider> frictionContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            SessionNarrativeCollector sessionNarrativeCollector,
            ProtectableWorkProfileCollector protectableWorkProfileCollector,
            RoleScopeCollector roleScopeCollector) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, frictionContextProviders,
                reasoningMemoryContextProviders, observedScopeInferenceService, sessionNarrativeCollector, protectableWorkProfileCollector,
                roleScopeCollector, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, List.of(), reasoningMemoryContextProviders,
                observedScopeInferenceService, null, null, null, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<FrictionContextProvider> frictionContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            CanonicalSecurityContextHardener contextHardener) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, frictionContextProviders,
                reasoningMemoryContextProviders, observedScopeInferenceService, null, null, null, contextHardener);
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<FrictionContextProvider> frictionContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            SessionNarrativeCollector sessionNarrativeCollector,
            ProtectableWorkProfileCollector protectableWorkProfileCollector,
            RoleScopeCollector roleScopeCollector,
            CanonicalSecurityContextHardener contextHardener) {
        this.resourceContextRegistry = resourceContextRegistry;
        this.coverageEvaluator = coverageEvaluator;
        this.authenticationContextProviders = authenticationContextProviders != null ? List.copyOf(authenticationContextProviders) : List.of();
        this.authorizationSnapshotProviders = authorizationSnapshotProviders != null ? List.copyOf(authorizationSnapshotProviders) : List.of();
        this.organizationContextProviders = organizationContextProviders != null ? List.copyOf(organizationContextProviders) : List.of();
        this.delegationContextProviders = delegationContextProviders != null ? List.copyOf(delegationContextProviders) : List.of();
        this.peerCohortContextProviders = peerCohortContextProviders != null ? List.copyOf(peerCohortContextProviders) : List.of();
        this.frictionContextProviders = frictionContextProviders != null ? List.copyOf(frictionContextProviders) : List.of();
        this.reasoningMemoryContextProviders = reasoningMemoryContextProviders != null ? List.copyOf(reasoningMemoryContextProviders) : List.of();
        this.observedScopeInferenceService = observedScopeInferenceService;
        this.sessionNarrativeCollector = sessionNarrativeCollector;
        this.protectableWorkProfileCollector = protectableWorkProfileCollector;
        this.roleScopeCollector = roleScopeCollector;
        this.contextHardener = contextHardener != null ? contextHardener : new CanonicalSecurityContextHardener();
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            List<PeerCohortContextProvider> peerCohortContextProviders,
            List<ReasoningMemoryContextProvider> reasoningMemoryContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            CanonicalSecurityContextHardener contextHardener) {
        this(resourceContextRegistry, coverageEvaluator, authenticationContextProviders, authorizationSnapshotProviders,
                organizationContextProviders, delegationContextProviders, peerCohortContextProviders, List.of(),
                reasoningMemoryContextProviders, observedScopeInferenceService, null, null, null, contextHardener);
    }

    @Override
    public Optional<CanonicalSecurityContext> resolve(SecurityEvent event) {
        if (event == null) {
            return Optional.empty();
        }

        Map<String, Object> metadata = prepareMetadata(event);

        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(resolveActor(event, metadata))
                .session(resolveSession(event, metadata))
                .resource(resolveResource(event, metadata))
                .authorization(resolveAuthorization(metadata))
                .bridge(resolveBridge(metadata))
                .attributes(new LinkedHashMap<>(metadata))
                .build();

        context.setDelegation(resolveDelegation(metadata, context));

        enrichFromRegistry(context);
        applyProviderContributions(event, context);
        inferObservedScope(event, context);
        context.setSessionNarrativeProfile(resolveSessionNarrativeProfile(metadata, context));
        context.setWorkProfile(resolveWorkProfile(metadata, context));
        context.setContextTrustProfiles(resolveContextTrustProfiles(metadata));
        context.setRoleScopeProfile(resolveRoleScopeProfile(metadata, context));
        context.setPeerCohortProfile(resolvePeerCohortProfile(metadata, context));
        context.setFrictionProfile(resolveFrictionProfile(metadata, context));
        context.setReasoningMemoryProfile(resolveReasoningMemoryProfile(metadata, context));
        contextHardener.harden(context);
        finalizeDelegation(context);
        context.setCoverage(coverageEvaluator.evaluate(context));
        return Optional.of(context);
    }

    private Map<String, Object> prepareMetadata(SecurityEvent event) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        if (event.getMetadata() != null) {
            metadata.putAll(event.getMetadata());
        }
        event.setMetadata(metadata);
        enrichSessionNarrativeMetadata(event, metadata);
        enrichProtectableWorkProfileMetadata(event, metadata);
        enrichRoleScopeMetadata(event, metadata);
        return metadata;
    }

    private void enrichSessionNarrativeMetadata(SecurityEvent event, Map<String, Object> metadata) {
        if (sessionNarrativeCollector == null) {
            return;
        }
        sessionNarrativeCollector.collect(event).ifPresent(snapshot -> {
            metadata.put("sessionNarrativeSummary", snapshot.getSummary());
            metadata.put("sessionAgeMinutes", snapshot.getSessionAgeMinutes());
            metadata.put("previousPath", snapshot.getPreviousPath());
            metadata.put("previousActionFamily", snapshot.getPreviousActionFamily());
            metadata.put("lastRequestIntervalMs", snapshot.getLastRequestIntervalMs());
            metadata.put("sessionActionSequence", snapshot.getSessionActionSequence());
            metadata.put("sessionProtectableSequence", snapshot.getSessionProtectableSequence());
            metadata.put("burstPattern", snapshot.getBurstPattern());
        });
    }

    private void enrichProtectableWorkProfileMetadata(SecurityEvent event, Map<String, Object> metadata) {
        if (protectableWorkProfileCollector == null) {
            return;
        }
        protectableWorkProfileCollector.collect(event).ifPresent(snapshot -> {
            metadata.put("workProfileSummary", snapshot.getSummary());
            metadata.put("frequentProtectableResources", snapshot.getFrequentProtectableResources());
            metadata.put("frequentActionFamilies", snapshot.getFrequentActionFamilies());
            metadata.put("normalAccessHours", snapshot.getNormalAccessHours());
            metadata.put("normalAccessDays", snapshot.getNormalAccessDays());
            metadata.put("normalRequestRate", snapshot.getNormalRequestRate());
            metadata.put("protectableInvocationDensity", snapshot.getProtectableInvocationDensity());
            metadata.put("protectableResourceHeatmap", snapshot.getProtectableResourceHeatmap());
            metadata.put("frequentSensitiveResourceCategories", snapshot.getFrequentSensitiveResourceCategories());
            metadata.put("normalReadWriteExportRatio", snapshot.getNormalReadWriteExportRatio());
            if (snapshot.getTrustProfile() != null) {
                metadata.put("workProfileTrustProfile", snapshot.getTrustProfile());
                metadata.put("workProfileProvenanceSummary", snapshot.getTrustProfile().getProvenanceSummary());
                metadata.put("workProfileQualityWarnings", snapshot.getTrustProfile().getQualityWarnings());
            }
        });
    }

    private void enrichRoleScopeMetadata(SecurityEvent event, Map<String, Object> metadata) {
        if (roleScopeCollector == null) {
            return;
        }
        roleScopeCollector.collect(event).ifPresent(snapshot -> {
            metadata.put("roleScopeSummary", snapshot.getSummary());
            metadata.put("currentResourceFamily", snapshot.getCurrentResourceFamily());
            metadata.put("currentActionFamily", snapshot.getCurrentActionFamily());
            metadata.put("expectedResourceFamilies", snapshot.getExpectedResourceFamilies());
            metadata.put("expectedActionFamilies", snapshot.getExpectedActionFamilies());
            metadata.put("forbiddenResourceFamilies", snapshot.getForbiddenResourceFamilies());
            metadata.put("forbiddenActionFamilies", snapshot.getForbiddenActionFamilies());
            metadata.put("normalApprovalPatterns", snapshot.getNormalApprovalPatterns());
            metadata.put("normalEscalationPatterns", snapshot.getNormalEscalationPatterns());
            metadata.put("recentPermissionChanges", snapshot.getRecentPermissionChanges());
            metadata.put("temporaryElevation", snapshot.getTemporaryElevation());
            metadata.put("temporaryElevationReason", snapshot.getTemporaryElevationReason());
            metadata.put("elevatedPrivilegeWindowActive", snapshot.getElevatedPrivilegeWindowActive());
            metadata.put("elevationWindowSummary", snapshot.getElevationWindowSummary());
            if (snapshot.getTrustProfile() != null) {
                metadata.put("roleScopeTrustProfile", snapshot.getTrustProfile());
                metadata.put("roleScopeProvenanceSummary", snapshot.getTrustProfile().getProvenanceSummary());
            }
        });
    }

    private List<ContextTrustProfile> resolveContextTrustProfiles(Map<String, Object> metadata) {
        List<ContextTrustProfile> trustProfiles = new ArrayList<>();
        Object workProfileTrustProfile = metadata.get("workProfileTrustProfile");
        if (workProfileTrustProfile instanceof ContextTrustProfile trustProfile) {
            trustProfiles.add(trustProfile);
        }
        Object roleScopeTrustProfile = metadata.get("roleScopeTrustProfile");
        if (roleScopeTrustProfile instanceof ContextTrustProfile trustProfile) {
            trustProfiles.add(trustProfile);
        }
        return List.copyOf(trustProfiles);
    }

    private CanonicalSecurityContext.Actor resolveActor(SecurityEvent event, Map<String, Object> metadata) {
        return CanonicalSecurityContext.Actor.builder()
                .userId(firstText(event.getUserId(), metadata.get("userId")))
                .externalSubjectId(firstText(metadata.get("externalSubjectId"), metadata.get("subjectId"), metadata.get("principalId"), metadata.get("sub")))
                .organizationId(firstText(metadata.get("organizationId"), metadata.get("orgId"), metadata.get("tenantId")))
                .tenantId(firstText(metadata.get("tenantId"), metadata.get("tenant_id"), metadata.get("organizationId")))
                .department(firstText(metadata.get("department"), metadata.get("team"), metadata.get("group")))
                .position(firstText(metadata.get("position"), metadata.get("jobTitle"), metadata.get("title")))
                .principalType(firstText(metadata.get("principalType"), metadata.get("principal.type"), metadata.get("userType")))
                .bridgeSubjectKey(firstText(metadata.get("bridgeSubjectKey"), metadata.get("bridge_subject_key")))
                .roleSet(normalizeStrings(metadata.get("userRoles"), metadata.get("roles"), metadata.get("roleSet")))
                .authoritySet(normalizeStrings(metadata.get("authorities"), metadata.get("permissions"), metadata.get("grantedAuthorities")))
                .build();
    }

    private CanonicalSecurityContext.Session resolveSession(SecurityEvent event, Map<String, Object> metadata) {
        return CanonicalSecurityContext.Session.builder()
                .sessionId(firstText(event.getSessionId(), metadata.get("sessionId")))
                .clientIp(firstText(event.getSourceIp(), metadata.get("clientIp")))
                .userAgent(firstText(event.getUserAgent(), metadata.get("userAgent")))
                .authenticationType(firstText(metadata.get("authenticationType"), metadata.get("authType"), metadata.get("auth_type")))
                .authenticationAssurance(firstText(metadata.get("authenticationAssurance"), metadata.get("authAssurance"), metadata.get("auth_assurance")))
                .mfaVerified(resolveBoolean(metadata.get("mfaVerified"), metadata.get("mfa_verified")))
                .recentMfaFailureCount(resolveInteger(metadata.get("recentMfaFailureCount"), metadata.get("recent_mfa_failure_count"), metadata.get("mfaFailureCount"), metadata.get("mfa_failure_count")))
                .lastMfaUsedAt(firstText(metadata.get("lastMfaUsedAt"), metadata.get("last_mfa_used_at"), metadata.get("lastUsedMfaAt")))
                .failedLoginAttempts(resolveInteger(metadata.get("failedLoginAttempts"), metadata.get("failed_login_attempts")))
                .recentRequestCount(resolveInteger(metadata.get("recentRequestCount"), metadata.get("recent_request_count")))
                .recentChallengeCount(resolveInteger(metadata.get("recentChallengeCount"), metadata.get("recent_challenge_count"), metadata.get("challengeCount")))
                .recentBlockCount(resolveInteger(metadata.get("recentBlockCount"), metadata.get("recent_block_count"), metadata.get("blockCount")))
                .recentEscalationCount(resolveInteger(metadata.get("recentEscalationCount"), metadata.get("recent_escalation_count"), metadata.get("escalationCount")))
                .blockedUser(resolveBoolean(metadata.get("blockedUser"), metadata.get("isBlockedUser"), metadata.get("blocked_user")))
                .newSession(resolveBoolean(metadata.get("isNewSession"), metadata.get("is_new_session")))
                .newUser(resolveBoolean(metadata.get("isNewUser"), metadata.get("is_new_user")))
                .newDevice(resolveBoolean(metadata.get("isNewDevice"), metadata.get("is_new_device")))
                .build();
    }

    private CanonicalSecurityContext.Resource resolveResource(SecurityEvent event, Map<String, Object> metadata) {
        String resourceId = firstText(metadata.get("resourceId"), metadata.get("requestPath"), metadata.get("httpUri"), event.getDescription());
        String httpMethod = firstText(metadata.get("httpMethod"), metadata.get("method"));
        return CanonicalSecurityContext.Resource.builder()
                .resourceId(resourceId)
                .resourceType(firstText(metadata.get("resourceType"), metadata.get("resourceCategory")))
                .businessLabel(firstText(metadata.get("resourceLabel"), metadata.get("businessLabel")))
                .sensitivity(firstText(metadata.get("resourceSensitivity"), metadata.get("sensitivity")))
                .requestPath(firstText(metadata.get("httpUri"), metadata.get("requestPath")))
                .httpMethod(httpMethod)
                .actionFamily(resolveActionFamily(httpMethod, metadata))
                .sensitiveResource(resolveBoolean(metadata.get("isSensitiveResource"), metadata.get("is_sensitive_resource")))
                .privileged(resolveBoolean(metadata.get("privileged"), metadata.get("isPrivileged")))
                .exportSensitive(resolveBoolean(metadata.get("exportSensitive"), metadata.get("isExportSensitive")))
                .build();
    }

    private CanonicalSecurityContext.Authorization resolveAuthorization(Map<String, Object> metadata) {
        return CanonicalSecurityContext.Authorization.builder()
                .effectiveRoles(normalizeStrings(metadata.get("effectiveRoles"), metadata.get("userRoles"), metadata.get("roles")))
                .effectivePermissions(normalizeStrings(metadata.get("effectivePermissions"), metadata.get("permissions"), metadata.get("authorities")))
                .scopeTags(normalizeStrings(metadata.get("scopeTags"), metadata.get("authorizationScope"), metadata.get("scope")))
                .authorizationEffect(firstText(metadata.get("authorizationEffect"), metadata.get("authorization_effect"), metadata.get("effect")))
                .policyId(firstText(metadata.get("policyId"), metadata.get("policy_id")))
                .policyVersion(firstText(metadata.get("policyVersion"), metadata.get("policy_version")))
                .privileged(resolveBoolean(metadata.get("privileged"), metadata.get("isPrivileged")))
                .build();
    }

    private CanonicalSecurityContext.Delegation resolveDelegation(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .agentId(firstText(metadata.get("agentId"), metadata.get("agent_id")))
                .objectiveId(firstText(metadata.get("objectiveId"), metadata.get("task_purpose")))
                .objectiveFamily(firstText(metadata.get("objectiveFamily"), metadata.get("objective_family")))
                .objectiveSummary(firstText(metadata.get("objectiveSummary"), metadata.get("objective_summary")))
                .allowedOperations(normalizeStrings(metadata.get("allowedOperations"), metadata.get("allowed_operations")))
                .allowedResources(normalizeStrings(metadata.get("allowedResources"), metadata.get("allowed_resources"), metadata.get("allowedResourceFamilies")))
                .approvalRequired(resolveBoolean(metadata.get("approvalRequired"), metadata.get("approval_required")))
                .privilegedExportAllowed(resolveBoolean(metadata.get("privilegedExportAllowed"), metadata.get("privileged_export_allowed")))
                .containmentOnly(resolveBoolean(metadata.get("containmentOnly"), metadata.get("containment_only")))
                .delegated(resolveBoolean(metadata.get("delegated"), metadata.get("isDelegated"), metadata.get("agentDelegated")))
                .objectiveDrift(resolveBoolean(metadata.get("objectiveDrift"), metadata.get("objective_drift"), metadata.get("delegationObjectiveDrift")))
                .objectiveDriftSummary(firstText(metadata.get("objectiveDriftSummary"), metadata.get("objective_drift_summary"), metadata.get("delegationObjectiveDriftSummary")))
                .build();

        if (delegation.getDelegated() == null) {
            delegation.setDelegated(computeDelegatedFlag(delegation));
        }
        return delegation;
    }

    private CanonicalSecurityContext.Bridge resolveBridge(Map<String, Object> metadata) {
        String coverageLevel = firstText(metadata.get("bridgeCoverageLevel"));
        Integer coverageScore = resolveInteger(metadata.get("bridgeCoverageScore"));
        List<String> missingContexts = normalizeStrings(metadata.get("bridgeMissingContexts"));
        String summary = firstText(metadata.get("bridgeCoverageSummary"));
        List<String> remediationHints = normalizeStrings(metadata.get("bridgeRemediationHints"));
        String authenticationSource = firstText(metadata.get("bridgeAuthenticationSource"));
        String authorizationSource = firstText(metadata.get("bridgeAuthorizationSource"));
        String delegationSource = firstText(metadata.get("bridgeDelegationSource"));
        if (!StringUtils.hasText(coverageLevel)
                && coverageScore == null
                && missingContexts.isEmpty()
                && !StringUtils.hasText(summary)
                && remediationHints.isEmpty()
                && !StringUtils.hasText(authenticationSource)
                && !StringUtils.hasText(authorizationSource)
                && !StringUtils.hasText(delegationSource)) {
            return null;
        }
        return CanonicalSecurityContext.Bridge.builder()
                .coverageLevel(coverageLevel)
                .coverageScore(coverageScore)
                .missingContexts(missingContexts)
                .summary(summary)
                .remediationHints(remediationHints)
                .authenticationSource(authenticationSource)
                .authorizationSource(authorizationSource)
                .delegationSource(delegationSource)
                .build();
    }

    private void enrichFromRegistry(CanonicalSecurityContext context) {
        resourceContextRegistry.findByEvent(context).ifPresent(descriptor -> {
            CanonicalSecurityContext.Resource resource = context.getResource();
            if (resource == null) {
                resource = new CanonicalSecurityContext.Resource();
                resource.setResourceId(descriptor.resourceId());
                context.setResource(resource);
            }
            if (!StringUtils.hasText(resource.getResourceType())) {
                resource.setResourceType(descriptor.resourceType());
            }
            if (!StringUtils.hasText(resource.getBusinessLabel())) {
                resource.setBusinessLabel(descriptor.businessLabel());
            }
            if (!StringUtils.hasText(resource.getSensitivity())) {
                resource.setSensitivity(descriptor.sensitivity());
            }
            if (resource.getPrivileged() == null) {
                resource.setPrivileged(descriptor.privileged());
            }
            if (resource.getExportSensitive() == null) {
                resource.setExportSensitive(descriptor.exportSensitive());
            }
            CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
            if (authorization != null && authorization.getScopeTags().isEmpty()) {
                authorization.setScopeTags(copyList(descriptor.allowedActionFamilies()));
            }
        });
    }

    private void applyProviderContributions(SecurityEvent event, CanonicalSecurityContext context) {
        for (AuthenticationContextProvider provider : authenticationContextProviders) {
            provider.enrich(event, context);
        }
        for (OrganizationContextProvider provider : organizationContextProviders) {
            provider.enrich(event, context);
        }
        for (AuthorizationSnapshotProvider provider : authorizationSnapshotProviders) {
            provider.enrich(event, context);
        }
        for (DelegationContextProvider provider : delegationContextProviders) {
            provider.enrich(event, context);
        }
        for (PeerCohortContextProvider provider : peerCohortContextProviders) {
            provider.enrich(event, context);
        }
        for (FrictionContextProvider provider : frictionContextProviders) {
            provider.enrich(event, context);
        }
        for (ReasoningMemoryContextProvider provider : reasoningMemoryContextProviders) {
            provider.enrich(event, context);
        }
    }

    private void inferObservedScope(SecurityEvent event, CanonicalSecurityContext context) {
        if (observedScopeInferenceService == null) {
            return;
        }
        observedScopeInferenceService.infer(event, context).ifPresent(context::setObservedScope);
    }

    private CanonicalSecurityContext.SessionNarrativeProfile resolveSessionNarrativeProfile(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile = CanonicalSecurityContext.SessionNarrativeProfile.builder()
                .summary(firstText(metadata.get("sessionNarrativeSummary")))
                .sessionAgeMinutes(resolveInteger(metadata.get("sessionAgeMinutes"), metadata.get("sessionAge"), metadata.get("session_age_minutes")))
                .previousPath(firstText(metadata.get("previousPath"), metadata.get("previous_path")))
                .previousActionFamily(firstText(
                        metadata.get("previousActionFamily"),
                        metadata.get("previous_action_family"),
                        metadata.get("previousAction")))
                .lastRequestIntervalMs(resolveLong(
                        metadata.get("lastRequestIntervalMs"),
                        metadata.get("lastRequestInterval"),
                        metadata.get("last_request_interval_ms")))
                .sessionActionSequence(normalizeStrings(
                        metadata.get("sessionActionSequence"),
                        metadata.get("recentSessionActions"),
                        metadata.get("sessionActions")))
                .sessionProtectableSequence(normalizeStrings(
                        metadata.get("sessionProtectableSequence"),
                        metadata.get("recentProtectableSequence"),
                        metadata.get("protectableSequence")))
                .burstPattern(resolveBoolean(
                        metadata.get("burstPattern"),
                        metadata.get("requestBurstPattern"),
                        metadata.get("burstDetected")))
                .build();

        if (!StringUtils.hasText(sessionNarrativeProfile.getSummary())) {
            sessionNarrativeProfile.setSummary(buildSessionNarrativeSummary(sessionNarrativeProfile, context));
        }

        if (!hasSessionNarrativeData(sessionNarrativeProfile)) {
            return null;
        }
        return sessionNarrativeProfile;
    }

    private CanonicalSecurityContext.WorkProfile resolveWorkProfile(Map<String, Object> metadata, CanonicalSecurityContext context) {
        List<String> frequentProtectableResources = normalizeStrings(
                metadata.get("topFrequentProtectableResources"),
                metadata.get("frequentProtectableResources"),
                metadata.get("baselineFrequentPaths"));
        if (frequentProtectableResources.isEmpty() && context.getObservedScope() != null) {
            frequentProtectableResources = copyList(context.getObservedScope().getFrequentResources());
        }

        List<String> frequentActionFamilies = normalizeStrings(
                metadata.get("frequentActionFamilies"),
                metadata.get("normalActionFamilies"),
                metadata.get("baselineActionFamilies"));
        if (frequentActionFamilies.isEmpty() && context.getObservedScope() != null) {
            frequentActionFamilies = copyList(context.getObservedScope().getFrequentActionFamilies());
        }

        List<Integer> normalAccessHours = resolveIntegerList(
                metadata.get("normalAccessHours"),
                metadata.get("baselineAccessHours"));
        List<Integer> normalAccessDays = resolveIntegerList(
                metadata.get("normalAccessDays"),
                metadata.get("baselineAccessDays"));
        Double normalRequestRate = resolveDouble(metadata.get("normalRequestRate"), metadata.get("baselineAvgRequestRate"));
        Integer normalSessionLengthMinutes = resolveInteger(metadata.get("normalSessionLengthMinutes"), metadata.get("baselineSessionLengthMinutes"));
        Double protectableInvocationDensity = resolveDouble(metadata.get("protectableInvocationDensity"));
        List<String> protectableResourceHeatmap = buildProtectableResourceHeatmap(metadata, context, frequentProtectableResources);

        if (protectableInvocationDensity == null
                && context.getObservedScope() != null
                && context.getObservedScope().getRecentProtectableAccessCount() != null
                && context.getSession() != null
                && context.getSession().getRecentRequestCount() != null
                && context.getSession().getRecentRequestCount() > 0) {
            protectableInvocationDensity = context.getObservedScope().getRecentProtectableAccessCount().doubleValue()
                    / context.getSession().getRecentRequestCount().doubleValue();
        }

        CanonicalSecurityContext.WorkProfile workProfile = CanonicalSecurityContext.WorkProfile.builder()
                .summary(firstText(metadata.get("workProfileSummary"), buildWorkProfileSummary(frequentProtectableResources, frequentActionFamilies, protectableInvocationDensity)))
                .frequentProtectableResources(frequentProtectableResources)
                .frequentActionFamilies(frequentActionFamilies)
                .frequentSensitiveResourceCategories(normalizeStrings(
                        metadata.get("frequentSensitiveResourceCategories"),
                        metadata.get("sensitiveResourceCategories"),
                        metadata.get("normalSensitiveResourceCategories")))
                .protectableResourceHeatmap(protectableResourceHeatmap)
                .normalAccessHours(normalAccessHours)
                .normalAccessDays(normalAccessDays)
                .normalRequestRate(normalRequestRate)
                .normalSessionLengthMinutes(normalSessionLengthMinutes)
                .normalReadWriteExportRatio(firstText(
                        metadata.get("normalReadWriteExportRatio"),
                        metadata.get("readWriteExportRatio")))
                .normalPrivilegedActionFrequency(resolveDouble(
                        metadata.get("normalPrivilegedActionFrequency"),
                        metadata.get("privilegedActionFrequency")))
                .protectableInvocationDensity(protectableInvocationDensity)
                .seasonalBusinessProfile(firstText(metadata.get("seasonalBusinessProfile"), metadata.get("seasonal_business_profile")))
                .longTailLegitimateTasks(normalizeStrings(metadata.get("longTailLegitimateTasks"), metadata.get("long_tail_legitimate_tasks")))
                .build();

        if (!hasWorkProfileData(workProfile)) {
            return null;
        }
        return workProfile;
    }

    private CanonicalSecurityContext.RoleScopeProfile resolveRoleScopeProfile(Map<String, Object> metadata, CanonicalSecurityContext context) {
        String currentResourceFamily = firstText(
                metadata.get("currentResourceFamily"),
                metadata.get("current_resource_family"),
                context.getResource() != null ? context.getResource().getResourceType() : null);
        String currentActionFamily = firstText(
                metadata.get("currentActionFamily"),
                metadata.get("current_action_family"),
                context.getResource() != null ? context.getResource().getActionFamily() : null);
        List<String> expectedResourceFamilies = normalizeStrings(metadata.get("expectedResourceFamilies"), metadata.get("allowedResourceFamilies"));
        List<String> expectedActionFamilies = normalizeStrings(metadata.get("expectedActionFamilies"), metadata.get("allowedActionFamilies"));
        List<String> forbiddenResourceFamilies = normalizeStrings(metadata.get("forbiddenResourceFamilies"), metadata.get("blockedResourceFamilies"));
        List<String> forbiddenActionFamilies = normalizeStrings(metadata.get("forbiddenActionFamilies"), metadata.get("blockedActionFamilies"));
        CanonicalSecurityContext.RoleScopeProfile roleScopeProfile = CanonicalSecurityContext.RoleScopeProfile.builder()
                .summary(firstText(metadata.get("roleScopeSummary")))
                .currentResourceFamily(currentResourceFamily)
                .currentActionFamily(currentActionFamily)
                .expectedResourceFamilies(expectedResourceFamilies)
                .expectedActionFamilies(expectedActionFamilies)
                .forbiddenResourceFamilies(forbiddenResourceFamilies)
                .forbiddenActionFamilies(forbiddenActionFamilies)
                .normalApprovalPatterns(normalizeStrings(metadata.get("normalApprovalPatterns"), metadata.get("approvalPatterns")))
                .normalEscalationPatterns(normalizeStrings(metadata.get("normalEscalationPatterns"), metadata.get("escalationPatterns")))
                .recentPermissionChanges(normalizeStrings(metadata.get("recentPermissionChanges"), metadata.get("permissionChangeEvents")))
                .resourceFamilyDrift(resolveBoolean(
                        metadata.get("resourceFamilyDrift"),
                        metadata.get("resource_family_drift")))
                .actionFamilyDrift(resolveBoolean(
                        metadata.get("actionFamilyDrift"),
                        metadata.get("action_family_drift")))
                .temporaryElevation(resolveBoolean(metadata.get("temporaryElevation"), metadata.get("temporary_elevation")))
                .temporaryElevationReason(firstText(metadata.get("temporaryElevationReason"), metadata.get("elevationReason"), metadata.get("temporary_elevation_reason")))
                .elevatedPrivilegeWindowActive(resolveBoolean(metadata.get("elevatedPrivilegeWindowActive"), metadata.get("elevated_privilege_window_active")))
                .elevationWindowSummary(firstText(metadata.get("elevationWindowSummary"), metadata.get("elevatedPrivilegeWindowSummary"), metadata.get("elevation_window_summary")))
                .build();

        if (!StringUtils.hasText(roleScopeProfile.getSummary())) {
            roleScopeProfile.setSummary(buildRoleScopeSummary(roleScopeProfile, context));
        }

        if (!hasRoleScopeData(roleScopeProfile)) {
            return null;
        }
        return roleScopeProfile;
    }

    private CanonicalSecurityContext.PeerCohortProfile resolvePeerCohortProfile(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.PeerCohortProfile existing = context.getPeerCohortProfile();
        CanonicalSecurityContext.PeerCohortProfile peerCohortProfile = CanonicalSecurityContext.PeerCohortProfile.builder()
                .cohortId(firstText(existing != null ? existing.getCohortId() : null, metadata.get("peerCohortId"), metadata.get("cohortId"), metadata.get("peer_cohort_id")))
                .summary(firstText(existing != null ? existing.getSummary() : null, metadata.get("peerCohortSummary"), metadata.get("cohortDeltaSummary"), metadata.get("cohortSummary")))
                .preferredResources(normalizeStrings(
                        existing != null ? existing.getPreferredResources() : null,
                        metadata.get("cohortPreferredResources"),
                        metadata.get("peerPreferredResources"),
                        metadata.get("peerCohortPreferredResources")))
                .preferredActionFamilies(normalizeStrings(
                        existing != null ? existing.getPreferredActionFamilies() : null,
                        metadata.get("cohortPreferredActionFamilies"),
                        metadata.get("peerPreferredActionFamilies"),
                        metadata.get("peerCohortPreferredActionFamilies")))
                .normalProtectableFrequencyBand(firstText(
                        existing != null ? existing.getNormalProtectableFrequencyBand() : null,
                        metadata.get("cohortNormalProtectableFrequencyBand"),
                        metadata.get("peerNormalProtectableFrequencyBand")))
                .normalSensitivityBand(firstText(
                        existing != null ? existing.getNormalSensitivityBand() : null,
                        metadata.get("cohortNormalSensitivityBand"),
                        metadata.get("peerNormalSensitivityBand")))
                .outlierAgainstCohort(resolveBoolean(
                        existing != null ? existing.getOutlierAgainstCohort() : null,
                        metadata.get("outlierAgainstCohort"),
                        metadata.get("cohortOutlier"),
                        metadata.get("peerOutlier")))
                .build();

        if (!StringUtils.hasText(peerCohortProfile.getSummary())) {
            peerCohortProfile.setSummary(buildPeerCohortSummary(peerCohortProfile, context));
        }

        if (!hasPeerCohortData(peerCohortProfile)) {
            return null;
        }
        return peerCohortProfile;
    }

    private CanonicalSecurityContext.FrictionProfile resolveFrictionProfile(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.FrictionProfile existing = context.getFrictionProfile();
        Integer recentDeniedAccessCount = resolveInteger(metadata.get("recentDeniedAccessCount"), metadata.get("recent_denied_access_count"));
        if (recentDeniedAccessCount == null && existing != null) {
            recentDeniedAccessCount = existing.getRecentDeniedAccessCount();
        }
        if (recentDeniedAccessCount == null && context.getObservedScope() != null) {
            recentDeniedAccessCount = context.getObservedScope().getRecentDeniedAccessCount();
        }

        Boolean approvalRequired = resolveBoolean(existing != null ? existing.getApprovalRequired() : null, metadata.get("approvalRequired"), metadata.get("approval_required"));
        if (approvalRequired == null && context.getDelegation() != null) {
            approvalRequired = context.getDelegation().getApprovalRequired();
        }
        String approvalStatus = firstText(existing != null ? existing.getApprovalStatus() : null, metadata.get("approvalStatus"), metadata.get("approval_status"));
        Boolean approvalGranted = resolveBoolean(existing != null ? existing.getApprovalGranted() : null, metadata.get("approvalGranted"), metadata.get("approval_granted"));
        if (approvalGranted == null && StringUtils.hasText(approvalStatus)) {
            approvalGranted = "APPROVED".equalsIgnoreCase(approvalStatus) || "GRANTED".equalsIgnoreCase(approvalStatus);
        }
        Boolean approvalMissing = resolveBoolean(existing != null ? existing.getApprovalMissing() : null);
        if (approvalMissing == null) {
            approvalMissing = resolveApprovalMissing(approvalRequired, approvalGranted, approvalStatus);
        }

        Integer recentChallengeCount = resolveInteger(metadata.get("recentChallengeCount"), metadata.get("recent_challenge_count"), metadata.get("challengeCount"));
        if (recentChallengeCount == null && existing != null) {
            recentChallengeCount = existing.getRecentChallengeCount();
        }
        if (recentChallengeCount == null && context.getSession() != null) {
            recentChallengeCount = context.getSession().getRecentChallengeCount();
        }
        Integer recentBlockCount = resolveInteger(metadata.get("recentBlockCount"), metadata.get("recent_block_count"), metadata.get("blockCount"));
        if (recentBlockCount == null && existing != null) {
            recentBlockCount = existing.getRecentBlockCount();
        }
        if (recentBlockCount == null && context.getSession() != null) {
            recentBlockCount = context.getSession().getRecentBlockCount();
        }
        Integer recentEscalationCount = resolveInteger(metadata.get("recentEscalationCount"), metadata.get("recent_escalation_count"), metadata.get("escalationCount"));
        if (recentEscalationCount == null && existing != null) {
            recentEscalationCount = existing.getRecentEscalationCount();
        }
        if (recentEscalationCount == null && context.getSession() != null) {
            recentEscalationCount = context.getSession().getRecentEscalationCount();
        }

        CanonicalSecurityContext.FrictionProfile frictionProfile = CanonicalSecurityContext.FrictionProfile.builder()
                .summary(firstText(existing != null ? existing.getSummary() : null, metadata.get("frictionProfileSummary")))
                .recentChallengeCount(recentChallengeCount)
                .recentBlockCount(recentBlockCount)
                .recentEscalationCount(recentEscalationCount)
                .approvalRequired(approvalRequired)
                .approvalGranted(approvalGranted)
                .approvalMissing(approvalMissing)
                .approvalStatus(approvalStatus)
                .approvalLineage(normalizeStrings(existing != null ? existing.getApprovalLineage() : null, metadata.get("approvalLineage"), metadata.get("approverLineage"), metadata.get("approval_lineage"), metadata.get("approverChain")))
                .pendingApproverRoles(normalizeStrings(existing != null ? existing.getPendingApproverRoles() : null, metadata.get("pendingApproverRoles"), metadata.get("pending_approver_roles"), metadata.get("approverRoles")))
                .approvalTicketId(firstText(existing != null ? existing.getApprovalTicketId() : null, metadata.get("approvalTicketId"), metadata.get("approvalRequestId"), metadata.get("approval_request_id"), metadata.get("requestId")))
                .approvalDecisionAgeMinutes(resolveInteger(existing != null ? existing.getApprovalDecisionAgeMinutes() : null, metadata.get("approvalDecisionAgeMinutes"), metadata.get("approvalAgeMinutes"), metadata.get("approval_age_minutes")))
                .breakGlass(resolveBoolean(existing != null ? existing.getBreakGlass() : null, metadata.get("breakGlass"), metadata.get("break_glass"), metadata.get("breakGlassRequested")))
                .recentDeniedAccessCount(recentDeniedAccessCount)
                .blockedUser(resolveBoolean(existing != null ? existing.getBlockedUser() : null, metadata.get("blockedUser"), metadata.get("isBlockedUser"), metadata.get("blocked_user")))
                .build();

        if (!StringUtils.hasText(frictionProfile.getSummary())) {
            frictionProfile.setSummary(buildFrictionSummary(frictionProfile));
        }

        if (!hasFrictionData(frictionProfile)) {
            return null;
        }
        return frictionProfile;
    }

    private CanonicalSecurityContext.ReasoningMemoryProfile resolveReasoningMemoryProfile(Map<String, Object> metadata, CanonicalSecurityContext context) {
        CanonicalSecurityContext.ReasoningMemoryProfile existing = context.getReasoningMemoryProfile();
        CanonicalSecurityContext.ReasoningMemoryProfile reasoningMemoryProfile = CanonicalSecurityContext.ReasoningMemoryProfile.builder()
                .summary(firstText(existing != null ? existing.getSummary() : null, metadata.get("reasoningMemorySummary"), metadata.get("reasoningSummary")))
                .reinforcedCaseCount(resolveLong(existing != null ? existing.getReinforcedCaseCount() : null, metadata.get("reinforcedCaseCount"), metadata.get("reinforcedCases")))
                .hardNegativeCaseCount(resolveLong(existing != null ? existing.getHardNegativeCaseCount() : null, metadata.get("hardNegativeCaseCount"), metadata.get("hardNegativeCases")))
                .falseNegativeCaseCount(resolveLong(existing != null ? existing.getFalseNegativeCaseCount() : null, metadata.get("falseNegativeCaseCount"), metadata.get("falseNegativeCases")))
                .knowledgeAssistedCaseCount(resolveLong(existing != null ? existing.getKnowledgeAssistedCaseCount() : null, metadata.get("knowledgeAssistedCaseCount"), metadata.get("knowledgeAssistedCases")))
                .objectiveAwareReasoningMemory(firstText(existing != null ? existing.getObjectiveAwareReasoningMemory() : null, metadata.get("objectiveAwareReasoningMemory"), metadata.get("objectiveAwareMemory")))
                .retentionTier(firstText(existing != null ? existing.getRetentionTier() : null, metadata.get("retentionTier"), metadata.get("reasoningRetentionTier")))
                .recallPriority(firstText(existing != null ? existing.getRecallPriority() : null, metadata.get("recallPriority"), metadata.get("reasoningRecallPriority")))
                .freshnessState(firstText(existing != null ? existing.getFreshnessState() : null, metadata.get("freshnessState"), metadata.get("reasoningFreshnessState")))
                .reasoningState(firstText(existing != null ? existing.getReasoningState() : null, metadata.get("reasoningState")))
                .cohortPreference(firstText(existing != null ? existing.getCohortPreference() : null, metadata.get("cohortPreference"), metadata.get("reasoningCohortPreference")))
                .memoryRiskProfile(firstText(existing != null ? existing.getMemoryRiskProfile() : null, metadata.get("memoryRiskProfile"), metadata.get("reasoningRiskProfile")))
                .retrievalWeight(resolveInteger(existing != null ? existing.getRetrievalWeight() : null, metadata.get("retrievalWeight"), metadata.get("reasoningRetrievalWeight")))
                .matchedSignalKeys(normalizeStrings(existing != null ? existing.getMatchedSignalKeys() : null, metadata.get("matchedSignalKeys"), metadata.get("threatKnowledgeSignalKeys"), metadata.get("threatKnowledgeKeys")))
                .objectiveFamilies(normalizeStrings(existing != null ? existing.getObjectiveFamilies() : null, metadata.get("objectiveFamilies"), metadata.get("objective_families")))
                .memoryGuardrails(normalizeStrings(existing != null ? existing.getMemoryGuardrails() : null, metadata.get("memoryGuardrails"), metadata.get("reasoningGuardrails"), metadata.get("reasoning_memory_guardrails")))
                .xaiLinkedFacts(normalizeStrings(existing != null ? existing.getXaiLinkedFacts() : null, metadata.get("xaiLinkedFacts"), metadata.get("xaiFacts"), metadata.get("xai_linked_facts")))
                .reasoningFacts(normalizeStrings(existing != null ? existing.getReasoningFacts() : null, metadata.get("reasoningFacts"), metadata.get("reasoning_facts")))
                .crossTenantObjectiveMisusePackSummary(firstText(existing != null ? existing.getCrossTenantObjectiveMisusePackSummary() : null, metadata.get("crossTenantObjectiveMisusePackSummary"), metadata.get("cross_tenant_objective_misuse_pack_summary")))
                .crossTenantObjectiveMisuseFacts(normalizeStrings(existing != null ? existing.getCrossTenantObjectiveMisuseFacts() : null, metadata.get("crossTenantObjectiveMisuseFacts"), metadata.get("cross_tenant_objective_misuse_facts")))
                .build();

        if (!StringUtils.hasText(reasoningMemoryProfile.getSummary())) {
            reasoningMemoryProfile.setSummary(buildReasoningMemorySummary(reasoningMemoryProfile, context));
        }

        if (!hasReasoningMemoryData(reasoningMemoryProfile)) {
            return null;
        }
        return reasoningMemoryProfile;
    }

    private String resolveActionFamily(String httpMethod, Map<String, Object> metadata) {
        String explicitAction = firstText(metadata.get("actionFamily"), metadata.get("operation"));
        if (StringUtils.hasText(explicitAction)) {
            return explicitAction.trim();
        }
        if (!StringUtils.hasText(httpMethod)) {
            return "UNKNOWN";
        }
        return switch (httpMethod.trim().toUpperCase(Locale.ROOT)) {
            case "GET", "HEAD" -> "READ";
            case "POST" -> "CREATE";
            case "PUT", "PATCH" -> "UPDATE";
            case "DELETE" -> "DELETE";
            default -> "UNKNOWN";
        };
    }

    private String firstText(Object... values) {
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString();
            if (!text.isBlank()) {
                return text;
            }
        }
        return null;
    }

    private Long resolveLong(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.longValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Long.parseLong(stringValue.trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private List<String> normalizeStrings(Object... rawValues) {
        Set<String> values = new LinkedHashSet<>();
        for (Object rawValue : rawValues) {
            if (rawValue == null) {
                continue;
            }
            if (rawValue instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addNormalized(values, item);
                }
                continue;
            }
            String text = rawValue.toString();
            if (text.contains(",")) {
                for (String token : text.split(",")) {
                    addNormalized(values, token);
                }
                continue;
            }
            addNormalized(values, text);
        }
        return List.copyOf(values);
    }

    private void addNormalized(Set<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String value = rawValue.toString().trim();
        if (!value.isBlank()) {
            values.add(value);
        }
    }

    private Boolean resolveBoolean(Object... values) {
        for (Object value : values) {
            if (value instanceof Boolean booleanValue) {
                return booleanValue;
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                return Boolean.parseBoolean(stringValue);
            }
        }
        return null;
    }

    private Integer resolveInteger(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Integer.parseInt(stringValue.trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private Double resolveDouble(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.doubleValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Double.parseDouble(stringValue.trim());
                }
                catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private List<Integer> resolveIntegerList(Object... values) {
        Set<Integer> results = new LinkedHashSet<>();
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            if (value instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addInteger(results, item);
                }
                continue;
            }
            String text = value.toString();
            if (text.contains(",")) {
                for (String token : text.split(",")) {
                    addInteger(results, token);
                }
                continue;
            }
            addInteger(results, text);
        }
        return List.copyOf(results);
    }

    private void addInteger(Set<Integer> results, Object rawValue) {
        Integer value = resolveInteger(rawValue);
        if (value != null) {
            results.add(value);
        }
    }

    private boolean hasWorkProfileData(CanonicalSecurityContext.WorkProfile workProfile) {
        return workProfile != null
                && (StringUtils.hasText(workProfile.getSummary())
                || !workProfile.getFrequentProtectableResources().isEmpty()
                || !workProfile.getFrequentActionFamilies().isEmpty()
                || !workProfile.getFrequentSensitiveResourceCategories().isEmpty()
                || !workProfile.getNormalAccessHours().isEmpty()
                || !workProfile.getNormalAccessDays().isEmpty()
                || workProfile.getNormalRequestRate() != null
                || workProfile.getNormalSessionLengthMinutes() != null
                || workProfile.getNormalReadWriteExportRatio() != null
                || workProfile.getNormalPrivilegedActionFrequency() != null
                || workProfile.getProtectableInvocationDensity() != null
                || !workProfile.getProtectableResourceHeatmap().isEmpty()
                || StringUtils.hasText(workProfile.getSeasonalBusinessProfile())
                || !workProfile.getLongTailLegitimateTasks().isEmpty());
    }

    private boolean hasSessionNarrativeData(CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile) {
        return sessionNarrativeProfile != null
                && (StringUtils.hasText(sessionNarrativeProfile.getSummary())
                || sessionNarrativeProfile.getSessionAgeMinutes() != null
                || StringUtils.hasText(sessionNarrativeProfile.getPreviousPath())
                || StringUtils.hasText(sessionNarrativeProfile.getPreviousActionFamily())
                || sessionNarrativeProfile.getLastRequestIntervalMs() != null
                || !sessionNarrativeProfile.getSessionActionSequence().isEmpty()
                || !sessionNarrativeProfile.getSessionProtectableSequence().isEmpty()
                || sessionNarrativeProfile.getBurstPattern() != null);
    }

    private boolean hasRoleScopeData(CanonicalSecurityContext.RoleScopeProfile roleScopeProfile) {
        return roleScopeProfile != null
                && (StringUtils.hasText(roleScopeProfile.getSummary())
                || StringUtils.hasText(roleScopeProfile.getCurrentResourceFamily())
                || StringUtils.hasText(roleScopeProfile.getCurrentActionFamily())
                || !roleScopeProfile.getExpectedResourceFamilies().isEmpty()
                || !roleScopeProfile.getExpectedActionFamilies().isEmpty()
                || !roleScopeProfile.getForbiddenResourceFamilies().isEmpty()
                || !roleScopeProfile.getForbiddenActionFamilies().isEmpty()
                || !roleScopeProfile.getNormalApprovalPatterns().isEmpty()
                || !roleScopeProfile.getNormalEscalationPatterns().isEmpty()
                || !roleScopeProfile.getRecentPermissionChanges().isEmpty()
                || roleScopeProfile.getTemporaryElevation() != null
                || StringUtils.hasText(roleScopeProfile.getTemporaryElevationReason())
                || roleScopeProfile.getElevatedPrivilegeWindowActive() != null
                || StringUtils.hasText(roleScopeProfile.getElevationWindowSummary()));
    }

    private boolean hasPeerCohortData(CanonicalSecurityContext.PeerCohortProfile peerCohortProfile) {
        return peerCohortProfile != null
                && (StringUtils.hasText(peerCohortProfile.getCohortId())
                || StringUtils.hasText(peerCohortProfile.getSummary())
                || !peerCohortProfile.getPreferredResources().isEmpty()
                || !peerCohortProfile.getPreferredActionFamilies().isEmpty()
                || StringUtils.hasText(peerCohortProfile.getNormalProtectableFrequencyBand())
                || StringUtils.hasText(peerCohortProfile.getNormalSensitivityBand())
                || peerCohortProfile.getOutlierAgainstCohort() != null);
    }

    private boolean hasFrictionData(CanonicalSecurityContext.FrictionProfile frictionProfile) {
        return frictionProfile != null
                && (StringUtils.hasText(frictionProfile.getSummary())
                || frictionProfile.getRecentChallengeCount() != null
                || frictionProfile.getRecentBlockCount() != null
                || frictionProfile.getRecentEscalationCount() != null
                || frictionProfile.getApprovalRequired() != null
                || frictionProfile.getApprovalGranted() != null
                || frictionProfile.getApprovalMissing() != null
                || StringUtils.hasText(frictionProfile.getApprovalStatus())
                || !frictionProfile.getApprovalLineage().isEmpty()
                || !frictionProfile.getPendingApproverRoles().isEmpty()
                || StringUtils.hasText(frictionProfile.getApprovalTicketId())
                || frictionProfile.getApprovalDecisionAgeMinutes() != null
                || frictionProfile.getBreakGlass() != null
                || frictionProfile.getRecentDeniedAccessCount() != null
                || frictionProfile.getBlockedUser() != null);
    }

    private boolean hasReasoningMemoryData(CanonicalSecurityContext.ReasoningMemoryProfile reasoningMemoryProfile) {
        return reasoningMemoryProfile != null
                && (StringUtils.hasText(reasoningMemoryProfile.getSummary())
                || reasoningMemoryProfile.getReinforcedCaseCount() != null
                || reasoningMemoryProfile.getHardNegativeCaseCount() != null
                || reasoningMemoryProfile.getFalseNegativeCaseCount() != null
                || reasoningMemoryProfile.getKnowledgeAssistedCaseCount() != null
                || StringUtils.hasText(reasoningMemoryProfile.getObjectiveAwareReasoningMemory())
                || StringUtils.hasText(reasoningMemoryProfile.getRetentionTier())
                || StringUtils.hasText(reasoningMemoryProfile.getRecallPriority())
                || StringUtils.hasText(reasoningMemoryProfile.getFreshnessState())
                || StringUtils.hasText(reasoningMemoryProfile.getReasoningState())
                || StringUtils.hasText(reasoningMemoryProfile.getCohortPreference())
                || StringUtils.hasText(reasoningMemoryProfile.getMemoryRiskProfile())
                || reasoningMemoryProfile.getRetrievalWeight() != null
                || !reasoningMemoryProfile.getMatchedSignalKeys().isEmpty()
                || !reasoningMemoryProfile.getObjectiveFamilies().isEmpty()
                || !reasoningMemoryProfile.getMemoryGuardrails().isEmpty()
                || !reasoningMemoryProfile.getXaiLinkedFacts().isEmpty()
                || !reasoningMemoryProfile.getReasoningFacts().isEmpty()
                || StringUtils.hasText(reasoningMemoryProfile.getCrossTenantObjectiveMisusePackSummary())
                || !reasoningMemoryProfile.getCrossTenantObjectiveMisuseFacts().isEmpty());
    }

    private Boolean resolveApprovalMissing(Boolean approvalRequired, Boolean approvalGranted, String approvalStatus) {
        if (!Boolean.TRUE.equals(approvalRequired)) {
            return null;
        }
        if (Boolean.TRUE.equals(approvalGranted)) {
            return false;
        }
        if (!StringUtils.hasText(approvalStatus)) {
            return true;
        }
        return "MISSING".equalsIgnoreCase(approvalStatus) || "NOT_FOUND".equalsIgnoreCase(approvalStatus);
    }

    private String buildWorkProfileSummary(List<String> frequentResources, List<String> frequentActionFamilies, Double protectableInvocationDensity) {
        List<String> facts = new ArrayList<>();
        if (!frequentResources.isEmpty()) {
            facts.add("Frequent protectable resources: " + String.join(", ", frequentResources));
        }
        if (!frequentActionFamilies.isEmpty()) {
            facts.add("Frequent action families: " + String.join(", ", frequentActionFamilies));
        }
        if (protectableInvocationDensity != null) {
            facts.add(String.format(Locale.ROOT, "Protectable invocation density: %.2f", protectableInvocationDensity));
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildSessionNarrativeSummary(
            CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile,
            CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (sessionNarrativeProfile.getSessionAgeMinutes() != null) {
            facts.add("Session age minutes: " + sessionNarrativeProfile.getSessionAgeMinutes());
        }
        if (StringUtils.hasText(sessionNarrativeProfile.getPreviousPath())) {
            facts.add("Previous path: " + sessionNarrativeProfile.getPreviousPath());
        }
        if (StringUtils.hasText(sessionNarrativeProfile.getPreviousActionFamily())) {
            facts.add("Previous action family: " + sessionNarrativeProfile.getPreviousActionFamily());
        }
        if (sessionNarrativeProfile.getLastRequestIntervalMs() != null) {
            facts.add("Last request interval ms: " + sessionNarrativeProfile.getLastRequestIntervalMs());
        }
        if (!sessionNarrativeProfile.getSessionActionSequence().isEmpty()) {
            facts.add("Session action sequence: " + String.join(", ", sessionNarrativeProfile.getSessionActionSequence()));
        }
        if (!sessionNarrativeProfile.getSessionProtectableSequence().isEmpty()) {
            facts.add("Protectable sequence: " + String.join(", ", sessionNarrativeProfile.getSessionProtectableSequence()));
        }
        if (Boolean.TRUE.equals(sessionNarrativeProfile.getBurstPattern())) {
            facts.add("Burst pattern is active");
        }
        if (facts.isEmpty() && context != null && context.getSession() != null && context.getSession().getRecentRequestCount() != null) {
            facts.add("Recent request count: " + context.getSession().getRecentRequestCount());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildRoleScopeSummary(CanonicalSecurityContext.RoleScopeProfile roleScopeProfile, CanonicalSecurityContext context) {
        if (context == null || context.getAuthorization() == null) {
            return roleScopeProfile == null ? null : buildRoleScopeSummaryWithoutAuthorization(roleScopeProfile);
        }
        List<String> facts = new ArrayList<>();
        if (!context.getAuthorization().getEffectiveRoles().isEmpty()) {
            facts.add("Effective roles: " + String.join(", ", context.getAuthorization().getEffectiveRoles()));
        }
        if (!context.getAuthorization().getScopeTags().isEmpty()) {
            facts.add("Scope tags: " + String.join(", ", context.getAuthorization().getScopeTags()));
        }
        if (Boolean.TRUE.equals(context.getAuthorization().getPrivileged())) {
            facts.add("Privileged flow is active");
        }
        if (roleScopeProfile != null && StringUtils.hasText(roleScopeProfile.getCurrentResourceFamily())) {
            facts.add("Current resource family: " + roleScopeProfile.getCurrentResourceFamily());
        }
        if (roleScopeProfile != null && StringUtils.hasText(roleScopeProfile.getCurrentActionFamily())) {
            facts.add("Current action family: " + roleScopeProfile.getCurrentActionFamily());
        }
        if (roleScopeProfile != null && !roleScopeProfile.getExpectedResourceFamilies().isEmpty()) {
            facts.add("Expected resource families: " + String.join(", ", roleScopeProfile.getExpectedResourceFamilies()));
        }
        if (roleScopeProfile != null && !roleScopeProfile.getExpectedActionFamilies().isEmpty()) {
            facts.add("Expected action families: " + String.join(", ", roleScopeProfile.getExpectedActionFamilies()));
        }
        if (roleScopeProfile != null && !roleScopeProfile.getForbiddenResourceFamilies().isEmpty()) {
            facts.add("Denied resource families: " + String.join(", ", roleScopeProfile.getForbiddenResourceFamilies()));
        }
        if (roleScopeProfile != null && !roleScopeProfile.getForbiddenActionFamilies().isEmpty()) {
            facts.add("Denied action families: " + String.join(", ", roleScopeProfile.getForbiddenActionFamilies()));
        }
        if (roleScopeProfile != null && Boolean.TRUE.equals(roleScopeProfile.getTemporaryElevation())) {
            facts.add("Temporary elevation is active");
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildRoleScopeSummaryWithoutAuthorization(CanonicalSecurityContext.RoleScopeProfile roleScopeProfile) {
        List<String> facts = new ArrayList<>();
        if (roleScopeProfile != null && StringUtils.hasText(roleScopeProfile.getCurrentResourceFamily())) {
            facts.add("Current resource family: " + roleScopeProfile.getCurrentResourceFamily());
        }
        if (roleScopeProfile != null && StringUtils.hasText(roleScopeProfile.getCurrentActionFamily())) {
            facts.add("Current action family: " + roleScopeProfile.getCurrentActionFamily());
        }
        if (roleScopeProfile != null && !roleScopeProfile.getExpectedResourceFamilies().isEmpty()) {
            facts.add("Expected resource families: " + String.join(", ", roleScopeProfile.getExpectedResourceFamilies()));
        }
        if (roleScopeProfile != null && !roleScopeProfile.getExpectedActionFamilies().isEmpty()) {
            facts.add("Expected action families: " + String.join(", ", roleScopeProfile.getExpectedActionFamilies()));
        }
        if (roleScopeProfile != null && !roleScopeProfile.getForbiddenResourceFamilies().isEmpty()) {
            facts.add("Denied resource families: " + String.join(", ", roleScopeProfile.getForbiddenResourceFamilies()));
        }
        if (roleScopeProfile != null && !roleScopeProfile.getForbiddenActionFamilies().isEmpty()) {
            facts.add("Denied action families: " + String.join(", ", roleScopeProfile.getForbiddenActionFamilies()));
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildPeerCohortSummary(
            CanonicalSecurityContext.PeerCohortProfile peerCohortProfile,
            CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (StringUtils.hasText(peerCohortProfile.getCohortId())) {
            facts.add("Peer cohort id: " + peerCohortProfile.getCohortId());
        }
        if (!peerCohortProfile.getPreferredResources().isEmpty()) {
            facts.add("Cohort preferred resources: " + String.join(", ", peerCohortProfile.getPreferredResources()));
        }
        if (!peerCohortProfile.getPreferredActionFamilies().isEmpty()) {
            facts.add("Cohort preferred action families: " + String.join(", ", peerCohortProfile.getPreferredActionFamilies()));
        }
        if (StringUtils.hasText(peerCohortProfile.getNormalProtectableFrequencyBand())) {
            facts.add("Cohort normal protectable frequency band: " + peerCohortProfile.getNormalProtectableFrequencyBand());
        }
        if (StringUtils.hasText(peerCohortProfile.getNormalSensitivityBand())) {
            facts.add("Cohort normal sensitivity band: " + peerCohortProfile.getNormalSensitivityBand());
        }
        if (facts.isEmpty() && context != null && context.getActor() != null && StringUtils.hasText(context.getActor().getDepartment())) {
            facts.add("Peer cohort reasoning is anchored to department " + context.getActor().getDepartment());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildFrictionSummary(CanonicalSecurityContext.FrictionProfile frictionProfile) {
        List<String> facts = new ArrayList<>();
        if (frictionProfile.getRecentChallengeCount() != null) {
            facts.add("Recent challenges: " + frictionProfile.getRecentChallengeCount());
        }
        if (frictionProfile.getRecentBlockCount() != null) {
            facts.add("Recent blocks: " + frictionProfile.getRecentBlockCount());
        }
        if (frictionProfile.getApprovalRequired() != null) {
            facts.add("Approval required: " + frictionProfile.getApprovalRequired());
        }
        if (StringUtils.hasText(frictionProfile.getApprovalStatus())) {
            facts.add("Approval status: " + frictionProfile.getApprovalStatus());
        }
        if (!frictionProfile.getApprovalLineage().isEmpty()) {
            facts.add("Approval lineage: " + String.join(", ", frictionProfile.getApprovalLineage()));
        }
        if (!frictionProfile.getPendingApproverRoles().isEmpty()) {
            facts.add("Pending approver roles: " + String.join(", ", frictionProfile.getPendingApproverRoles()));
        }
        if (StringUtils.hasText(frictionProfile.getApprovalTicketId())) {
            facts.add("Approval ticket id: " + frictionProfile.getApprovalTicketId());
        }
        if (frictionProfile.getApprovalDecisionAgeMinutes() != null) {
            facts.add("Approval decision age minutes: " + frictionProfile.getApprovalDecisionAgeMinutes());
        }
        if (frictionProfile.getRecentDeniedAccessCount() != null) {
            facts.add("Recent denied access count: " + frictionProfile.getRecentDeniedAccessCount());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private String buildReasoningMemorySummary(
            CanonicalSecurityContext.ReasoningMemoryProfile reasoningMemoryProfile,
            CanonicalSecurityContext context) {
        List<String> facts = new ArrayList<>();
        if (reasoningMemoryProfile.getReinforcedCaseCount() != null) {
            facts.add("Reinforced cases: " + reasoningMemoryProfile.getReinforcedCaseCount());
        }
        if (reasoningMemoryProfile.getHardNegativeCaseCount() != null) {
            facts.add("Hard negative cases: " + reasoningMemoryProfile.getHardNegativeCaseCount());
        }
        if (reasoningMemoryProfile.getFalseNegativeCaseCount() != null) {
            facts.add("False negative cases: " + reasoningMemoryProfile.getFalseNegativeCaseCount());
        }
        if (reasoningMemoryProfile.getKnowledgeAssistedCaseCount() != null) {
            facts.add("Knowledge-assisted cases: " + reasoningMemoryProfile.getKnowledgeAssistedCaseCount());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getObjectiveAwareReasoningMemory())) {
            facts.add("Objective-aware reasoning memory: " + reasoningMemoryProfile.getObjectiveAwareReasoningMemory());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getRetentionTier())) {
            facts.add("Retention tier: " + reasoningMemoryProfile.getRetentionTier());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getRecallPriority())) {
            facts.add("Recall priority: " + reasoningMemoryProfile.getRecallPriority());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getFreshnessState())) {
            facts.add("Freshness state: " + reasoningMemoryProfile.getFreshnessState());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getReasoningState())) {
            facts.add("Reasoning state: " + reasoningMemoryProfile.getReasoningState());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getCohortPreference())) {
            facts.add("Cohort preference: " + reasoningMemoryProfile.getCohortPreference());
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getMemoryRiskProfile())) {
            facts.add("Memory risk profile: " + reasoningMemoryProfile.getMemoryRiskProfile());
        }
        if (reasoningMemoryProfile.getRetrievalWeight() != null) {
            facts.add("Retrieval weight: " + reasoningMemoryProfile.getRetrievalWeight());
        }
        if (!reasoningMemoryProfile.getMatchedSignalKeys().isEmpty()) {
            facts.add("Matched signal keys: " + String.join(", ", reasoningMemoryProfile.getMatchedSignalKeys()));
        }
        if (!reasoningMemoryProfile.getObjectiveFamilies().isEmpty()) {
            facts.add("Objective families: " + String.join(", ", reasoningMemoryProfile.getObjectiveFamilies()));
        }
        if (!reasoningMemoryProfile.getMemoryGuardrails().isEmpty()) {
            facts.add("Memory guardrails: " + String.join(", ", reasoningMemoryProfile.getMemoryGuardrails()));
        }
        if (!reasoningMemoryProfile.getReasoningFacts().isEmpty()) {
            facts.add("Reasoning facts: " + String.join(", ", reasoningMemoryProfile.getReasoningFacts()));
        }
        if (StringUtils.hasText(reasoningMemoryProfile.getCrossTenantObjectiveMisusePackSummary())) {
            facts.add("Cross-tenant objective misuse pack: " + reasoningMemoryProfile.getCrossTenantObjectiveMisusePackSummary());
        }
        if (!reasoningMemoryProfile.getCrossTenantObjectiveMisuseFacts().isEmpty()) {
            facts.add("Cross-tenant misuse facts: " + String.join(", ", reasoningMemoryProfile.getCrossTenantObjectiveMisuseFacts()));
        }
        if (facts.isEmpty() && context != null && context.getDelegation() != null && StringUtils.hasText(context.getDelegation().getObjectiveFamily())) {
            facts.add("Reasoning memory is objective-aware for " + context.getDelegation().getObjectiveFamily());
        }
        return facts.isEmpty() ? null : String.join(" | ", facts);
    }

    private List<String> buildProtectableResourceHeatmap(
            Map<String, Object> metadata,
            CanonicalSecurityContext context,
            List<String> frequentProtectableResources) {
        List<String> explicitHeatmap = normalizeStrings(
                metadata.get("protectableResourceHeatmap"),
                metadata.get("protectable_heatmap"),
                metadata.get("protectableResourceCounts"));
        if (!explicitHeatmap.isEmpty()) {
            return explicitHeatmap;
        }

        Object history = metadata.get("protectableAccessHistory");
        if (history instanceof Collection<?> collection && !collection.isEmpty()) {
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (Object item : collection) {
                if (!(item instanceof Map<?, ?> entry)) {
                    continue;
                }
                String resourceId = firstText(entry.get("resourceId"), entry.get("requestPath"), entry.get("path"));
                if (!StringUtils.hasText(resourceId)) {
                    continue;
                }
                counts.merge(resourceId, 1, Integer::sum);
            }
            if (!counts.isEmpty()) {
                return counts.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                                .thenComparing(Map.Entry.comparingByKey()))
                        .limit(6)
                        .map(entry -> entry.getKey() + "=" + entry.getValue())
                        .toList();
            }
        }

        if (frequentProtectableResources != null && !frequentProtectableResources.isEmpty()) {
            return frequentProtectableResources.stream()
                    .limit(6)
                    .map(item -> item + "=OBSERVED")
                    .toList();
        }

        if (context != null && context.getObservedScope() != null && !context.getObservedScope().getFrequentResources().isEmpty()) {
            return context.getObservedScope().getFrequentResources().stream()
                    .limit(6)
                    .map(item -> item + "=OBSERVED")
                    .toList();
        }
        return List.of();
    }

    private Boolean computeDelegatedFlag(CanonicalSecurityContext.Delegation delegation) {
        if (delegation == null) {
            return null;
        }
        if (StringUtils.hasText(delegation.getAgentId())
                || StringUtils.hasText(delegation.getObjectiveId())
                || StringUtils.hasText(delegation.getObjectiveFamily())
                || StringUtils.hasText(delegation.getObjectiveSummary())
                || !delegation.getAllowedOperations().isEmpty()
                || !delegation.getAllowedResources().isEmpty()
                || delegation.getApprovalRequired() != null
                || delegation.getPrivilegedExportAllowed() != null
                || delegation.getContainmentOnly() != null) {
            return true;
        }
        return null;
    }

    private void finalizeDelegation(CanonicalSecurityContext context) {
        if (context == null || context.getDelegation() == null) {
            return;
        }
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        if (delegation.getDelegated() == null) {
            delegation.setDelegated(computeDelegatedFlag(delegation));
        }
        ObjectiveDriftEvaluation evaluation = objectiveDriftEvaluator.evaluate(delegation, context);
        if (delegation.getObjectiveDrift() == null) {
            delegation.setObjectiveDrift(evaluation.objectiveDrift());
        }
        if (!StringUtils.hasText(delegation.getObjectiveDriftSummary())) {
            delegation.setObjectiveDriftSummary(buildDelegationDriftSummary(delegation, evaluation));
        }
    }

    private String buildDelegationDriftSummary(
            CanonicalSecurityContext.Delegation delegation,
            ObjectiveDriftEvaluation evaluation) {
        if (delegation == null || (!Boolean.TRUE.equals(delegation.getDelegated())
                && !StringUtils.hasText(delegation.getObjectiveId())
                && !StringUtils.hasText(delegation.getObjectiveFamily())
                && !StringUtils.hasText(delegation.getObjectiveSummary()))) {
            return null;
        }
        List<String> facts = new ArrayList<>();
        facts.add(Boolean.TRUE.equals(delegation.getObjectiveDrift()) || Boolean.FALSE.equals(delegation.getObjectiveDrift())
                ? "Delegated objective comparison evidence is available."
                : "Delegated objective comparison is incomplete because comparable delegated action/resource family inputs are missing.");
        if (StringUtils.hasText(delegation.getObjectiveFamily())) {
            facts.add("Objective family: " + delegation.getObjectiveFamily());
        }
        if (StringUtils.hasText(delegation.getObjectiveSummary())) {
            facts.add("Objective summary: " + delegation.getObjectiveSummary());
        }
        if (evaluation != null) {
            facts.addAll(evaluation.facts());
        }
        return String.join(" | ", facts);
    }

    private List<String> copyList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(values);
    }

}

