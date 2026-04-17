package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.resolver.*;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.springframework.util.StringUtils;

import java.util.*;

import static io.contexa.contexacore.autonomous.context.support.MetadataValueResolver.*;
import static io.contexa.contexacore.autonomous.context.support.IdentityTokenNormalizer.*;
import io.contexa.contexacore.autonomous.context.collector.ProtectableWorkProfileCollector;
import io.contexa.contexacore.autonomous.context.collector.RoleScopeCollector;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeCollector;
import io.contexa.contexacore.autonomous.context.enricher.AuthenticationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.AuthorizationSnapshotProvider;
import io.contexa.contexacore.autonomous.context.enricher.ContextEnricher;
import io.contexa.contexacore.autonomous.context.enricher.DelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.OrganizationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.PeerCohortContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.ReasoningMemoryContextProvider;
import io.contexa.contexacore.autonomous.context.hardener.CanonicalSecurityContextHardener;
import io.contexa.contexacore.autonomous.context.inference.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.inference.MetadataObservedScopeInferenceService;
import io.contexa.contexacore.autonomous.context.inference.ObjectiveDriftEvaluator;
import io.contexa.contexacore.autonomous.context.inference.ObservedScopeInferenceService;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.context.model.ObjectiveDriftEvaluation;
import io.contexa.contexacore.autonomous.context.registry.ResourceContextRegistry;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;

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
    private final CanonicalExecutionContextResolver canonicalExecutionContextResolver = new CanonicalExecutionContextResolver();
    private final List<ProfileResolver<?>> profileResolvers = List.of(
            new SessionNarrativeProfileResolver(),
            new WorkProfileResolver(),
            new RoleScopeProfileResolver(),
            new PeerCohortProfileResolver(),
            new FrictionProfileResolver(),
            new ReasoningMemoryProfileResolver()
    );

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

        CanonicalSecurityContext.Session session = resolveSession(event, metadata);
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(resolveActor(event, metadata))
                .session(session)
                .device(resolveDevice(metadata, session))
                .intent(resolveIntent(metadata))
                .location(resolveLocation(metadata, session))
                .resource(resolveResource(event, metadata))
                .authorization(resolveAuthorization(metadata))
                .bridge(resolveBridge(metadata))
                .attributes(new LinkedHashMap<>(metadata))
                .build();

        context.setDelegation(resolveDelegation(metadata, context));

        enrichFromRegistry(context);
        applyProviderContributions(event, context);
        inferObservedScope(event, context);
        for (ProfileResolver<?> resolver : profileResolvers) {
            applyProfile(resolver, metadata, context);
        }
        context.setContextTrustProfiles(resolveContextTrustProfiles(metadata));
        contextHardener.harden(context);
        finalizeDelegation(context);
        context.setExecutionSubject(canonicalExecutionContextResolver.resolveSubject(context));
        context.setExecutionEnvelope(canonicalExecutionContextResolver.resolveEnvelope(context));
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
            backfillMetadata(metadata, "sessionNarrativeSummary", snapshot.getSummary());
            backfillMetadata(metadata, "sessionAgeMinutes", snapshot.getSessionAgeMinutes());
            backfillMetadata(metadata, "previousPath", snapshot.getPreviousPath());
            backfillMetadata(metadata, "previousActionFamily", snapshot.getPreviousActionFamily());
            backfillMetadata(metadata, "lastRequestIntervalMs", snapshot.getLastRequestIntervalMs());
            backfillMetadata(metadata, "sessionActionSequence", snapshot.getSessionActionSequence());
            backfillMetadata(metadata, "sessionProtectableSequence", snapshot.getSessionProtectableSequence());
            backfillMetadata(metadata, "burstPattern", snapshot.getBurstPattern());
        });
    }

    private void enrichProtectableWorkProfileMetadata(SecurityEvent event, Map<String, Object> metadata) {
        if (protectableWorkProfileCollector == null) {
            return;
        }
        protectableWorkProfileCollector.collect(event).ifPresent(snapshot -> {
            backfillMetadata(metadata, "workProfileSummary", snapshot.getSummary());
            backfillMetadata(metadata, "frequentProtectableResources", snapshot.getFrequentProtectableResources());
            backfillMetadata(metadata, "frequentActionFamilies", snapshot.getFrequentActionFamilies());
            backfillMetadata(metadata, "normalAccessHours", snapshot.getNormalAccessHours());
            backfillMetadata(metadata, "normalAccessDays", snapshot.getNormalAccessDays());
            backfillMetadata(metadata, "normalRequestRate", snapshot.getNormalRequestRate());
            backfillMetadata(metadata, "protectableInvocationDensity", snapshot.getProtectableInvocationDensity());
            backfillMetadata(metadata, "protectableResourceHeatmap", snapshot.getProtectableResourceHeatmap());
            backfillMetadata(metadata, "frequentSensitiveResourceCategories", snapshot.getFrequentSensitiveResourceCategories());
            backfillMetadata(metadata, "normalReadWriteExportRatio", snapshot.getNormalReadWriteExportRatio());
            if (snapshot.getTrustProfile() != null) {
                backfillMetadata(metadata, "workProfileTrustProfile", snapshot.getTrustProfile());
                backfillMetadata(metadata, "workProfileProvenanceSummary", snapshot.getTrustProfile().getProvenanceSummary());
                backfillMetadata(metadata, "workProfileQualityWarnings", snapshot.getTrustProfile().getQualityWarnings());
            }
        });
    }

    private void enrichRoleScopeMetadata(SecurityEvent event, Map<String, Object> metadata) {
        if (roleScopeCollector == null) {
            return;
        }
        roleScopeCollector.collect(event).ifPresent(snapshot -> {
            backfillMetadata(metadata, "roleScopeSummary", snapshot.getSummary());
            backfillMetadata(metadata, "currentResourceFamily", snapshot.getCurrentResourceFamily());
            backfillMetadata(metadata, "currentActionFamily", snapshot.getCurrentActionFamily());
            backfillMetadata(metadata, "expectedResourceFamilies", snapshot.getExpectedResourceFamilies());
            backfillMetadata(metadata, "expectedActionFamilies", snapshot.getExpectedActionFamilies());
            backfillMetadata(metadata, "forbiddenResourceFamilies", snapshot.getForbiddenResourceFamilies());
            backfillMetadata(metadata, "forbiddenActionFamilies", snapshot.getForbiddenActionFamilies());
            backfillMetadata(metadata, "normalApprovalPatterns", snapshot.getNormalApprovalPatterns());
            backfillMetadata(metadata, "normalEscalationPatterns", snapshot.getNormalEscalationPatterns());
            backfillMetadata(metadata, "recentPermissionChanges", snapshot.getRecentPermissionChanges());
            backfillMetadata(metadata, "temporaryElevation", snapshot.getTemporaryElevation());
            backfillMetadata(metadata, "temporaryElevationReason", snapshot.getTemporaryElevationReason());
            backfillMetadata(metadata, "elevatedPrivilegeWindowActive", snapshot.getElevatedPrivilegeWindowActive());
            backfillMetadata(metadata, "elevationWindowSummary", snapshot.getElevationWindowSummary());
            if (snapshot.getTrustProfile() != null) {
                backfillMetadata(metadata, "roleScopeTrustProfile", snapshot.getTrustProfile());
                backfillMetadata(metadata, "roleScopeProvenanceSummary", snapshot.getTrustProfile().getProvenanceSummary());
            }
        });
    }

    private void backfillMetadata(Map<String, Object> metadata, String key, Object value) {
        if (metadata == null || key == null || value == null) {
            return;
        }
        if (!metadata.containsKey(key) || metadata.get(key) == null) {
            metadata.put(key, value);
        }
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
                .roleSet(normalizeRoleStrings(metadata.get("userRoles"), metadata.get("roles"), metadata.get("roleSet")))
                .authoritySet(normalizeAuthorityStrings(metadata.get("authorities"), metadata.get("permissions"), metadata.get("grantedAuthorities")))
                .build();
    }

    private CanonicalSecurityContext.Session resolveSession(SecurityEvent event, Map<String, Object> metadata) {
        Integer accessHour = resolveInteger(
                metadata.get("currentAccessHour"),
                metadata.get("accessHour"),
                event != null && event.getTimestamp() != null ? event.getTimestamp().getHour() : null);
        return CanonicalSecurityContext.Session.builder()
                .sessionId(firstText(event.getSessionId(), metadata.get("sessionId")))
                .clientIp(firstText(event.getSourceIp(), metadata.get("clientIp")))
                .userAgent(firstText(event.getUserAgent(), metadata.get("userAgent")))
                .authenticationType(firstText(metadata.get("authenticationType"), metadata.get("authType"), metadata.get("auth_type")))
                .authenticationAssurance(firstText(metadata.get("authenticationAssurance"), metadata.get("authAssurance"), metadata.get("auth_assurance")))
                .mfaVerified(resolveBoolean(metadata.get("mfaVerified"), metadata.get("mfa_verified")))
                .recentMfaFailureCount(resolveInteger(metadata.get("recentMfaFailureCount"), metadata.get("recent_mfa_failure_count"), metadata.get("mfaFailureCount"), metadata.get("mfa_failure_count")))
                .lastMfaUsedAt(firstText(metadata.get("lastMfaUsedAt"), metadata.get("last_mfa_used_at"), metadata.get("lastUsedMfaAt")))
                .failedLoginAttempts(resolveInteger(metadata.get("failedLoginAttempts"), metadata.get("failed_login_attempts"), metadata.get("recentLoginFailures")))
                .recentRequestCount(resolveInteger(metadata.get("recentRequestCount"), metadata.get("recent_request_count"), metadata.get("requestRateMultiplier")))
                .recentChallengeCount(resolveInteger(metadata.get("recentChallengeCount"), metadata.get("recent_challenge_count"), metadata.get("challengeCount")))
                .recentBlockCount(resolveInteger(metadata.get("recentBlockCount"), metadata.get("recent_block_count"), metadata.get("blockCount")))
                .recentEscalationCount(resolveInteger(metadata.get("recentEscalationCount"), metadata.get("recent_escalation_count"), metadata.get("escalationCount")))
                .blockedUser(resolveBoolean(metadata.get("blockedUser"), metadata.get("isBlockedUser"), metadata.get("blocked_user")))
                .newSession(resolveBoolean(metadata.get("isNewSession"), metadata.get("is_new_session")))
                .newUser(resolveBoolean(metadata.get("isNewUser"), metadata.get("is_new_user")))
                .newDevice(resolveBoolean(metadata.get("isNewDevice"), metadata.get("is_new_device")))
                .currentAccessHour(accessHour)
                .concurrentSessions(resolveInteger(metadata.get("concurrentSessions"), metadata.get("currentConcurrentSessions")))
                .passwordAgeDays(resolveInteger(metadata.get("passwordAgeDays"), metadata.get("daysSincePasswordChange")))
                .build();
    }

    private CanonicalSecurityContext.Device resolveDevice(Map<String, Object> metadata, CanonicalSecurityContext.Session session) {
        String userAgent = session != null ? session.getUserAgent() : null;
        String browserSignature = firstText(
                metadata.get("deviceBrowserSignature"),
                metadata.get("browserSignature"),
                SecurityEventEnricher.extractBrowserSignature(userAgent));
        String[] browserParts = splitNameAndVersion(browserSignature);
        String browser = firstText(metadata.get("deviceBrowser"), metadata.get("browser"), browserParts[0]);
        String browserVersion = firstText(metadata.get("deviceBrowserVersion"), metadata.get("browserVersion"), browserParts[1]);
        String os = firstText(metadata.get("deviceOs"), metadata.get("os"), SecurityEventEnricher.extractOSFromUserAgent(userAgent));
        String osVersion = firstText(metadata.get("deviceOsVersion"), metadata.get("osVersion"));
        CanonicalSecurityContext.Device device = CanonicalSecurityContext.Device.builder()
                .os(os)
                .osVersion(osVersion)
                .browser(browser)
                .browserVersion(browserVersion)
                .screenResolution(firstText(metadata.get("deviceScreenResolution"), metadata.get("screenResolution")))
                .language(firstText(metadata.get("deviceLanguage"), metadata.get("language"), metadata.get("acceptLanguage")))
                .fingerprintMatch(resolveBoolean(metadata.get("deviceFingerprintMatch"), metadata.get("fingerprintMatch")))
                .build();
        return hasDeviceData(device) ? device : null;
    }

    private CanonicalSecurityContext.Intent resolveIntent(Map<String, Object> metadata) {
        CanonicalSecurityContext.Intent intent = CanonicalSecurityContext.Intent.builder()
                .botUserAgent(resolveBoolean(metadata.get("intentBotUserAgent"), metadata.get("botUserAgent")))
                .missingReferer(resolveBoolean(metadata.get("intentMissingReferer"), metadata.get("missingReferer")))
                .languageMismatch(resolveBoolean(metadata.get("intentLanguageMismatch"), metadata.get("languageMismatch")))
                .tlsFingerprintAltered(resolveBoolean(metadata.get("intentTlsFingerprintAltered"), metadata.get("tlsFingerprintAltered")))
                .abnormalHeaderOrder(resolveBoolean(metadata.get("intentAbnormalHeaderOrder"), metadata.get("abnormalHeaderOrder")))
                .impossibleTravel(resolveBoolean(metadata.get("intentImpossibleTravel"), metadata.get("impossibleTravel"), metadata.get("isImpossibleTravel")))
                .build();
        return hasIntentData(intent) ? intent : null;
    }

    private CanonicalSecurityContext.Location resolveLocation(Map<String, Object> metadata, CanonicalSecurityContext.Session session) {
        String clientIp = session != null ? session.getClientIp() : null;
        CanonicalSecurityContext.Location location = CanonicalSecurityContext.Location.builder()
                .country(firstText(metadata.get("country"), metadata.get("geoCountry")))
                .city(firstText(metadata.get("city"), metadata.get("geoCity")))
                .ipBand(firstText(metadata.get("ipBand"), deriveIpBand(clientIp)))
                .asn(firstText(metadata.get("asn"), metadata.get("geoAsn")))
                .build();
        return hasLocationData(location) ? location : null;
    }

    private CanonicalSecurityContext.Resource resolveResource(SecurityEvent event, Map<String, Object> metadata) {
        String resourceId = firstText(metadata.get("resourceId"), metadata.get("requestPath"), metadata.get("httpUri"), event.getDescription());
        String httpMethod = firstText(metadata.get("httpMethod"), metadata.get("method"));
        Boolean sensitiveResource = resolveBoolean(metadata.get("isSensitiveResource"), metadata.get("is_sensitive_resource"));
        Boolean privileged = resolveBoolean(metadata.get("privileged"), metadata.get("isPrivileged"));
        Boolean exportSensitive = resolveBoolean(metadata.get("exportSensitive"), metadata.get("isExportSensitive"));
        return CanonicalSecurityContext.Resource.builder()
                .resourceId(resourceId)
                .resourceType(firstText(metadata.get("resourceType"), metadata.get("resourceCategory")))
                .businessLabel(firstText(metadata.get("resourceLabel"), metadata.get("businessLabel")))
                .sensitivity(resolveResourceSensitivity(metadata, sensitiveResource, privileged, exportSensitive))
                .requestPath(firstText(metadata.get("httpUri"), metadata.get("requestPath")))
                .httpMethod(httpMethod)
                .actionFamily(resolveActionFamily(httpMethod, metadata))
                .sensitiveResource(sensitiveResource)
                .privileged(privileged)
                .exportSensitive(exportSensitive)
                .build();
    }

    private boolean hasDeviceData(CanonicalSecurityContext.Device device) {
        return device != null
                && (StringUtils.hasText(device.getOs())
                || StringUtils.hasText(device.getOsVersion())
                || StringUtils.hasText(device.getBrowser())
                || StringUtils.hasText(device.getBrowserVersion())
                || StringUtils.hasText(device.getScreenResolution())
                || StringUtils.hasText(device.getLanguage())
                || device.getFingerprintMatch() != null);
    }

    private boolean hasIntentData(CanonicalSecurityContext.Intent intent) {
        return intent != null
                && (intent.getBotUserAgent() != null
                || intent.getMissingReferer() != null
                || intent.getLanguageMismatch() != null
                || intent.getTlsFingerprintAltered() != null
                || intent.getAbnormalHeaderOrder() != null
                || intent.getImpossibleTravel() != null);
    }

    private boolean hasLocationData(CanonicalSecurityContext.Location location) {
        return location != null
                && (StringUtils.hasText(location.getCountry())
                || StringUtils.hasText(location.getCity())
                || StringUtils.hasText(location.getIpBand())
                || StringUtils.hasText(location.getAsn()));
    }

    private String[] splitNameAndVersion(String signature) {
        if (!StringUtils.hasText(signature)) {
            return new String[] { null, null };
        }
        String normalized = signature.trim();
        int separator = normalized.indexOf('/');
        if (separator < 0) {
            return new String[] { normalized, null };
        }
        String name = normalized.substring(0, separator).trim();
        String version = normalized.substring(separator + 1).trim();
        return new String[] {
                StringUtils.hasText(name) ? name : null,
                StringUtils.hasText(version) ? version : null
        };
    }

    private String deriveIpBand(String clientIp) {
        if (!StringUtils.hasText(clientIp)) {
            return null;
        }
        String normalized = clientIp.trim();
        String[] ipv4 = normalized.split("\\.");
        if (ipv4.length == 4) {
            return ipv4[0] + "." + ipv4[1] + "." + ipv4[2] + ".0/24";
        }
        if (normalized.contains(":")) {
            String[] ipv6 = normalized.split(":");
            if (ipv6.length >= 4) {
                return String.join(":", ipv6[0], ipv6[1], ipv6[2], ipv6[3]) + "::/64";
            }
        }
        return null;
    }

    private String resolveResourceSensitivity(
            Map<String, Object> metadata,
            Boolean sensitiveResource,
            Boolean privileged,
            Boolean exportSensitive) {
        String explicitSensitivity = firstText(metadata.get("resourceSensitivity"), metadata.get("sensitivity"));
        if (StringUtils.hasText(explicitSensitivity)) {
            return explicitSensitivity;
        }
        if (Boolean.TRUE.equals(sensitiveResource)
                || Boolean.TRUE.equals(privileged)
                || Boolean.TRUE.equals(exportSensitive)) {
            return "HIGH";
        }
        return null;
    }

    private CanonicalSecurityContext.Authorization resolveAuthorization(Map<String, Object> metadata) {
        return CanonicalSecurityContext.Authorization.builder()
                .effectiveRoles(normalizeRoleStrings(metadata.get("effectiveRoles"), metadata.get("userRoles"), metadata.get("roles")))
                .effectivePermissions(normalizePermissionStrings(metadata.get("effectivePermissions"), metadata.get("permissions"), metadata.get("authorities")))
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
        enrichAll(authenticationContextProviders, event, context);
        enrichAll(organizationContextProviders, event, context);
        enrichAll(authorizationSnapshotProviders, event, context);
        enrichAll(delegationContextProviders, event, context);
        enrichAll(peerCohortContextProviders, event, context);
        enrichAll(frictionContextProviders, event, context);
        enrichAll(reasoningMemoryContextProviders, event, context);
    }

    private void enrichAll(List<? extends ContextEnricher> enrichers, SecurityEvent event, CanonicalSecurityContext context) {
        for (ContextEnricher enricher : enrichers) {
            enricher.enrich(event, context);
        }
    }

    private void inferObservedScope(SecurityEvent event, CanonicalSecurityContext context) {
        if (observedScopeInferenceService == null) {
            return;
        }
        observedScopeInferenceService.infer(event, context).ifPresent(context::setObservedScope);
    }


    private <T> void applyProfile(ProfileResolver<T> resolver, Map<String, Object> metadata, CanonicalSecurityContext context) {
        resolver.resolve(metadata, context).ifPresent(profile -> resolver.apply(profile, context));
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
