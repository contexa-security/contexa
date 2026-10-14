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

import io.contexa.contexacore.autonomous.context.resolver.*;
import io.contexa.contexacommon.domain.SecurityEvent;
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
import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.NetworkZone;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;

@Slf4j
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
        Map<String, Object> attributes = new LinkedHashMap<>(metadata);
        applyCanonicalAliasDiagnostics(event, metadata, attributes);

        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(resolveActor(event, metadata))
                .session(session)
                .device(resolveDevice(metadata, session))
                .intent(resolveIntent(metadata))
                .location(resolveLocation(metadata, session))
                .resource(resolveResource(event, metadata))
                .authorization(resolveAuthorization(metadata))
                .bridge(resolveBridge(metadata))
                .attributes(attributes)
                .requestObservedAt(event.getTimestamp())
                .build();
        context.setDataConflicts(resolveDataConflicts(metadata, attributes));

        context.setDelegation(resolveDelegation(metadata, context));

        enrichFromRegistry(context);
        applyProviderContributions(event, context);
        classifyResource(context, metadata);
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

    private void applyCanonicalAliasDiagnostics(
            SecurityEvent event,
            Map<String, Object> metadata,
            Map<String, Object> attributes) {
        Map<String, Object> aliases = new LinkedHashMap<>();
        List<Map<String, Object>> conflicts = new ArrayList<>();

        addAliasDiagnostics(aliases, conflicts, "actor.userId",
                firstText(event.getUserId(), metadata.get("userId")),
                aliasSources(
                        "event.userId", event.getUserId(),
                        "metadata.userId", metadata.get("userId")));
        addAliasDiagnostics(aliases, conflicts, "actor.organizationId",
                firstText(metadata.get("organizationId"), metadata.get("orgId")),
                aliasSources(
                        "metadata.organizationId", metadata.get("organizationId"),
                        "metadata.orgId", metadata.get("orgId")));
        addAliasDiagnostics(aliases, conflicts, "actor.tenantId",
                firstText(metadata.get("tenantId"), metadata.get("tenant_id")),
                aliasSources(
                        "metadata.tenantId", metadata.get("tenantId"),
                        "metadata.tenant_id", metadata.get("tenant_id")));
        addAliasDiagnostics(aliases, conflicts, "session.sessionId",
                firstText(event.getSessionId(), metadata.get("sessionId")),
                aliasSources(
                        "event.sessionId", event.getSessionId(),
                        "metadata.sessionId", metadata.get("sessionId")));
        addAliasDiagnostics(aliases, conflicts, "session.clientIp",
                firstText(event.getSourceIp(), metadata.get("clientIp")),
                aliasSources(
                        "event.sourceIp", event.getSourceIp(),
                        "metadata.clientIp", metadata.get("clientIp")));
        addAliasDiagnostics(aliases, conflicts, "session.userAgent",
                firstText(event.getUserAgent(), metadata.get("userAgent")),
                aliasSources(
                        "event.userAgent", event.getUserAgent(),
                        "metadata.userAgent", metadata.get("userAgent")));
        addAliasDiagnostics(aliases, conflicts, "session.mfaVerified",
                firstText(metadata.get("mfaVerified"), metadata.get("mfa_verified")),
                aliasSources(
                        "metadata.mfaVerified", metadata.get("mfaVerified"),
                        "metadata.mfa_verified", metadata.get("mfa_verified")));
        addAliasDiagnostics(aliases, conflicts, "resource.resourceId",
                firstText(metadata.get("resourceId"), metadata.get("requestPath"), metadata.get("httpUri"), event.getDescription()),
                aliasSources(
                        "metadata.resourceId", metadata.get("resourceId"),
                        "metadata.managedResourceId", metadata.get("managedResourceId"),
                        "metadata.endpointKey", metadata.get("endpointKey")));
        addAliasDiagnostics(aliases, conflicts, "resource.requestPath",
                firstText(metadata.get("httpUri"), metadata.get("requestPath")),
                aliasSources(
                        "metadata.httpUri", metadata.get("httpUri"),
                        "metadata.requestPath", metadata.get("requestPath"),
                        "metadata.resourceUrl", metadata.get("resourceUrl")));
        addAliasDiagnostics(aliases, conflicts, "resource.httpMethod",
                firstText(metadata.get("httpMethod"), metadata.get("method")),
                aliasSources(
                        "metadata.httpMethod", metadata.get("httpMethod"),
                        "metadata.method", metadata.get("method")));
        addAliasDiagnostics(aliases, conflicts, "resource.sensitivity",
                firstText(metadata.get("resourceSensitivity"), metadata.get("sensitivity")),
                aliasSources(
                        "metadata.resourceSensitivity", metadata.get("resourceSensitivity"),
                        "metadata.sensitivity", metadata.get("sensitivity")));
        addAliasDiagnostics(aliases, conflicts, "authorization.authorizationEffect",
                firstText(metadata.get("authorizationEffect"), metadata.get("authorization_effect"), metadata.get("effect")),
                aliasSources(
                        "metadata.authorizationEffect", metadata.get("authorizationEffect"),
                        "metadata.authorization_effect", metadata.get("authorization_effect"),
                        "metadata.effect", metadata.get("effect")));
        addAliasDiagnostics(aliases, conflicts, "authorization.policyId",
                firstText(metadata.get("policyId"), metadata.get("policy_id")),
                aliasSources(
                        "metadata.policyId", metadata.get("policyId"),
                        "metadata.policy_id", metadata.get("policy_id")));
        addAliasDiagnostics(aliases, conflicts, "authorization.policyVersion",
                firstText(metadata.get("policyVersion"), metadata.get("policy_version")),
                aliasSources(
                        "metadata.policyVersion", metadata.get("policyVersion"),
                        "metadata.policy_version", metadata.get("policy_version")));

        if (!aliases.isEmpty()) {
            attributes.put("canonicalAliases", aliases);
        }
        if (!conflicts.isEmpty()) {
            attributes.put("canonicalConflicts", conflicts);
        }
    }

    private Map<String, Object> aliasSources(Object... pairs) {
        Map<String, Object> sources = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            Object key = pairs[i];
            if (key != null) {
                sources.put(String.valueOf(key), pairs[i + 1]);
            }
        }
        return sources;
    }

    private void addAliasDiagnostics(
            Map<String, Object> aliases,
            List<Map<String, Object>> conflicts,
            String field,
            String selected,
            Map<String, Object> sources) {
        Map<String, String> presentSources = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : sources.entrySet()) {
            String value = diagnosticText(entry.getValue());
            if (StringUtils.hasText(value)) {
                presentSources.put(entry.getKey(), value);
            }
        }
        if (presentSources.isEmpty()) {
            return;
        }

        Map<String, Object> alias = new LinkedHashMap<>();
        alias.put("selected", selected);
        alias.put("sources", presentSources);
        aliases.put(field, alias);

        Map<String, String> distinctValues = new LinkedHashMap<>();
        for (String value : presentSources.values()) {
            String normalized = normalizeDiagnosticValue(value);
            if (StringUtils.hasText(normalized)) {
                distinctValues.putIfAbsent(normalized, value);
            }
        }
        if (distinctValues.size() > 1) {
            Map<String, Object> conflict = new LinkedHashMap<>();
            conflict.put("field", field);
            conflict.put("selected", selected);
            conflict.put("sources", presentSources);
            conflict.put("distinctValues", new ArrayList<>(distinctValues.values()));
            conflicts.add(conflict);
        }
    }

    private String diagnosticText(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return StringUtils.hasText(text) ? text : null;
    }

    private String normalizeDiagnosticValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }

    private void enrichSessionNarrativeMetadata(SecurityEvent event, Map<String, Object> metadata) {
        if (sessionNarrativeCollector == null) {
            return;
        }
        sessionNarrativeCollector.collect(event).ifPresent(snapshot -> {
            backfillMetadata(metadata, "sessionNarrativeSummary", snapshot.getSummary());
            backfillMetadata(metadata, "sessionAgeMinutes", snapshot.getSessionAgeMinutes());
            backfillMetadata(metadata, "sessionAgeBasis", snapshot.getSessionAgeBasis());
            backfillMetadata(metadata, "isNewSession", snapshot.getNewSession());
            backfillMetadata(metadata, "previousPath", snapshot.getPreviousPath());
            backfillMetadata(metadata, "previousActionFamily", snapshot.getPreviousActionFamily());
            backfillMetadata(metadata, "lastRequestIntervalMs", snapshot.getLastRequestIntervalMs());
            backfillMetadata(metadata, "sessionActionSequence", snapshot.getSessionActionSequence());
            backfillMetadata(metadata, "sessionProtectableSequence", snapshot.getSessionProtectableSequence());
            backfillMetadata(metadata, "burstPattern", snapshot.getBurstPattern());
            backfillMetadata(metadata, "recentChallengeCount", snapshot.getRecentChallengeCount());
            backfillMetadata(metadata, "recentBlockCount", snapshot.getRecentBlockCount());
            backfillMetadata(metadata, "recentEscalationCount", snapshot.getRecentEscalationCount());
            backfillMetadata(metadata, "sessionDeviceChange", snapshot.getSessionDeviceChange());
            backfillMetadata(metadata, "sessionNetworkChange", snapshot.getSessionNetworkChange());
            if (snapshot.getSessionDecisionHistory() != null && !snapshot.getSessionDecisionHistory().isEmpty()) {
                backfillMetadata(metadata, "sessionDecisionHistory", snapshot.getSessionDecisionHistory());
            }
            if (snapshot.getSessionDecisions() != null && !snapshot.getSessionDecisions().isEmpty()) {
                backfillMetadata(metadata, SessionDecisionRecord.METADATA_KEY, snapshot.getSessionDecisions());
            }
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
            BaselineView view = snapshot.getBaselineView();
            if (view != null && view.observed()) {
                // The usual session length, privileged share and rare legitimate tasks had no producer (W2-3, S-29).
                backfillMetadata(metadata, "workProfileBaselineView", view);
                backfillMetadata(metadata, "normalSessionLengthMinutes", view.usualSessionMinutes());
                backfillMetadata(metadata, "normalPrivilegedActionFrequency",
                        Math.round(view.privilegedActions() * 10_000.0 / view.observations()) / 10_000.0);
                backfillMetadata(metadata, "longTailLegitimateTasks",
                        view.knownRareTasks().isEmpty() ? null : view.knownRareTasks());
            }
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
            // The request's action family is not written back: under currentActionFamily, a host key, the family the
            // core inferred would read as one the host declared. Every reader resolves it from the request's facts.
            backfillMetadata(metadata, "expectedResourceFamilies", snapshot.getExpectedResourceFamilies());
            backfillMetadata(metadata, "expectedActionFamilies", snapshot.getExpectedActionFamilies());
            backfillMetadata(metadata, "forbiddenResourceFamilies", snapshot.getForbiddenResourceFamilies());
            backfillMetadata(metadata, "forbiddenActionFamilies", snapshot.getForbiddenActionFamilies());
            backfillMetadata(metadata, "currentResourceFamilyInDeniedScope", snapshot.getCurrentResourceFamilyInDeniedScope());
            backfillMetadata(metadata, "currentActionFamilyInDeniedScope", snapshot.getCurrentActionFamilyInDeniedScope());
            backfillMetadata(metadata, "deniedScopeComparedByPair", true);
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
                .organizationId(firstText(metadata.get("organizationId"), metadata.get("orgId")))
                .tenantId(firstText(metadata.get("tenantId"), metadata.get("tenant_id")))
                .department(firstText(metadata.get("department"), metadata.get("team"), metadata.get("group")))
                .accountCreatedAt(firstText(metadata.get("accountCreatedAt")))
                .position(firstText(metadata.get("position"), metadata.get("jobTitle"), metadata.get("title")))
                .principalType(firstText(metadata.get("principalType"), metadata.get("principal.type"), metadata.get("userType")))
                .bridgeSubjectKey(firstText(metadata.get("bridgeSubjectKey"), metadata.get("bridge_subject_key")))
                .roleSet(normalizeRoleStrings(metadata.get("userRoles"), metadata.get("roles"), metadata.get("roleSet")))
                .authoritySet(normalizeAuthorityStrings(metadata.get("authorities"), metadata.get("permissions"), metadata.get("grantedAuthorities")))
                .build();
    }

    private CanonicalSecurityContext.Session resolveSession(SecurityEvent event, Map<String, Object> metadata) {
        Integer accessHour = resolveInteger(
                event != null && event.getTimestamp() != null ? event.getLocalTimestamp().getHour() : null,
                metadata.get("currentAccessHour"),
                metadata.get("accessHour"));
        return CanonicalSecurityContext.Session.builder()
                .sessionId(firstText(event.getSessionId(), metadata.get("sessionId")))
                .clientIp(firstText(event.getSourceIp(), metadata.get("clientIp")))
                .userAgent(firstText(event.getUserAgent(), metadata.get("userAgent")))
                .authenticationType(firstText(
                        metadata.get("authMethod"),
                        metadata.get("auth_method"),
                        metadata.get("authenticationType"),
                        metadata.get("authType"),
                        metadata.get("auth_type")))
                .authenticationAssurance(firstText(metadata.get("authenticationAssurance"), metadata.get("authAssurance"), metadata.get("auth_assurance")))
                .authenticationTime(firstText(metadata.get("authenticationTime"), metadata.get("authentication_time")))
                .mfaVerified(resolveBoolean(metadata.get("mfaVerified"), metadata.get("mfa_verified")))
                .recentMfaFailureCount(resolveInteger(metadata.get("recentMfaFailureCount"), metadata.get("recent_mfa_failure_count"), metadata.get("mfaFailureCount"), metadata.get("mfa_failure_count")))
                .lastMfaUsedAt(firstText(metadata.get("lastMfaUsedAt"), metadata.get("last_mfa_used_at"), metadata.get("lastUsedMfaAt")))
                .challengeVerifiedAt(firstText(metadata.get("challengeVerifiedAt")))
                .recentMfaElsewhereAt(firstText(metadata.get("recentMfaElsewhereAt")))
                .failedLoginAttempts(resolveInteger(metadata.get("failedLoginAttempts"), metadata.get("failed_login_attempts"), metadata.get("recentLoginFailures")))
                .failedLoginWindowMinutes(resolveInteger(metadata.get("failedLoginWindowMinutes")))
                .recentRequestCount(resolveInteger(metadata.get("recentRequestCount"), metadata.get("recent_request_count")))
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
        String os = SecuritySemanticNormalizer.normalizeOperatingSystem(
                metadata.get("deviceOs"), metadata.get("os"), SecurityEventEnricher.extractOSFromUserAgent(userAgent));
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
                .anomalySignal(firstText(metadata.get("anomalySignal")))
                .anomalySignalSource(firstText(metadata.get("anomalySignalSource")))
                .untrustedAnomalySignalClaim(firstText(metadata.get("untrustedAnomalySignalClaim")))
                .build();
        return hasIntentData(intent) ? intent : null;
    }

    private CanonicalSecurityContext.Location resolveLocation(Map<String, Object> metadata, CanonicalSecurityContext.Session session) {
        String clientIp = session != null ? session.getClientIp() : null;
        CanonicalSecurityContext.Location location = CanonicalSecurityContext.Location.builder()
                .country(firstText(metadata.get("country"), metadata.get("geoCountry")))
                .city(firstText(metadata.get("city"), metadata.get("geoCity")))
                .ipBand(SecuritySemanticNormalizer.normalizeNetwork(clientIp, firstText(metadata.get("ipBand"))))
                .asn(firstText(metadata.get("asn"), metadata.get("geoAsn")))
                .networkZone(NetworkZone.nameOf(metadata.get("networkZone")))
                .movement(resolveMovement(metadata))
                .build();
        return hasLocationData(location) ? location : null;
    }

    /** The host's move facts, whether or not it also states an impossible travel (W2-13). */
    private CanonicalSecurityContext.Movement resolveMovement(Map<String, Object> metadata) {
        CanonicalSecurityContext.Movement movement = CanonicalSecurityContext.Movement.builder()
                .latitude(resolveDouble(metadata.get("geoLatitude"), metadata.get("latitude")))
                .longitude(resolveDouble(metadata.get("geoLongitude"), metadata.get("longitude")))
                .distanceKm(resolveInteger(metadata.get("travelDistanceKm")))
                .elapsedMinutes(resolveInteger(metadata.get("travelElapsedMinutes")))
                .previousLocation(firstText(metadata.get("previousLocation")))
                .baselineConfidence(resolveDouble(metadata.get("baselineConfidence")))
                .build();
        boolean stated = movement.getLatitude() != null || movement.getLongitude() != null
                || movement.getDistanceKm() != null || movement.getElapsedMinutes() != null
                || StringUtils.hasText(movement.getPreviousLocation());
        return stated ? movement : null;
    }

    private CanonicalSecurityContext.Resource resolveResource(SecurityEvent event, Map<String, Object> metadata) {
        String resourceId = firstText(metadata.get("resourceId"), metadata.get("requestPath"), metadata.get("httpUri"), event.getDescription());
        String httpMethod = firstText(metadata.get("httpMethod"), metadata.get("method"));
        Boolean sensitiveResource = resolveBoolean(metadata.get("isSensitiveResource"), metadata.get("is_sensitive_resource"));
        Boolean verificationRequired = resolveBoolean(
                metadata.get("protectableVerificationRequired"), metadata.get("verificationRequired"));
        Boolean privileged = resolveBoolean(
                metadata.get("privileged"), metadata.get("protectablePrivileged"), metadata.get("isPrivileged"));
        Boolean exportSensitive = resolveBoolean(metadata.get("exportSensitive"), metadata.get("isExportSensitive"));
        ActionFamilyResolver.Resolution action = ActionFamilyResolver.resolve(metadata);
        String requestPath = firstText(metadata.get("httpUri"), metadata.get("requestPath"));
        return CanonicalSecurityContext.Resource.builder()
                .resourceId(resourceId)
                .resourceType(firstText(metadata.get("resourceType"), metadata.get("resourceCategory")))
                .businessLabel(firstText(metadata.get("resourceLabel"), metadata.get("businessLabel")))
                .authorText(firstText(metadata.get("resourceAuthorText")))
                .requestedItems(resolveInteger(metadata.get("requestItems")))
                .sensitivity(resolveResourceSensitivity(metadata, sensitiveResource, privileged, exportSensitive))
                .requestPath(requestPath)
                .pathFamily(SecuritySemanticNormalizer.pathFamilyOf(metadata, requestPath))
                .httpMethod(httpMethod)
                .actionFamily(action.family().name())
                .actionFamilySource(action.source())
                .sensitiveResource(sensitiveResource)
                .verificationRequired(verificationRequired)
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
                || intent.getImpossibleTravel() != null
                || StringUtils.hasText(intent.getAnomalySignal())
                || StringUtils.hasText(intent.getAnomalySignalSource())
                || StringUtils.hasText(intent.getUntrustedAnomalySignalClaim()));
    }

    private boolean hasLocationData(CanonicalSecurityContext.Location location) {
        return location != null
                && (StringUtils.hasText(location.getCountry())
                || StringUtils.hasText(location.getCity())
                || StringUtils.hasText(location.getIpBand())
                || StringUtils.hasText(location.getAsn())
                || StringUtils.hasText(location.getNetworkZone())
                || location.getMovement() != null);
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
                .methodExecutionOutcome(firstText(metadata.get("methodExecutionOutcome")))
                .methodExecutionFailure(firstText(metadata.get("methodExecutionFailure")))
                .policyId(firstText(metadata.get("policyId"), metadata.get("policy_id")))
                .policyVersion(firstText(metadata.get("policyVersion"), metadata.get("policy_version")))
                .privileged(resolveBoolean(metadata.get("privileged"), metadata.get("isPrivileged")))
                .decisionTime(firstText(metadata.get("authorizationDecisionTime")))
                .privilegedAuthoritySignals(normalizeStrings(metadata.get("privilegedAuthoritySignals")))
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
                .approvalRequired(resolveBoolean(metadata.get("delegationApprovalRequired"),
                        metadata.get("delegation_approval_required")))
                .privilegedExportAllowed(resolveBoolean(metadata.get("privilegedExportAllowed"), metadata.get("privileged_export_allowed")))
                .containmentOnly(resolveBoolean(metadata.get("containmentOnly"), metadata.get("containment_only")))
                .delegated(resolveBoolean(metadata.get("delegated"), metadata.get("isDelegated"), metadata.get("agentDelegated")))
                .objectiveDrift(resolveBoolean(metadata.get("objectiveDrift"), metadata.get("objective_drift"), metadata.get("delegationObjectiveDrift")))
                .objectiveDriftSummary(firstText(metadata.get("objectiveDriftSummary"), metadata.get("objective_drift_summary"), metadata.get("delegationObjectiveDriftSummary")))
                .expiresAt(firstText(metadata.get("delegationExpiresAt")))
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
        String finalAuthorizationEffect = firstText(metadata.get("authorizationEffect"));
        boolean authorizationEffectResolved = StringUtils.hasText(finalAuthorizationEffect)
                && !"UNKNOWN".equalsIgnoreCase(finalAuthorizationEffect);
        if (authorizationEffectResolved) {
            missingContexts = missingContexts.stream()
                    .filter(value -> !"AUTHORIZATION_EFFECT".equalsIgnoreCase(value))
                    .toList();
            remediationHints = remediationHints.stream()
                    .filter(value -> value == null
                            || !value.toLowerCase(Locale.ROOT).contains("authorization effect"))
                    .toList();
        }
        String authenticationSource = firstText(metadata.get("bridgeAuthenticationSource"));
        String authorizationSource = firstText(metadata.get("bridgeAuthorizationSource"));
        String delegationSource = firstText(metadata.get("bridgeDelegationSource"));
        Map<String, String> evidenceStates = bridgeEvidenceStates(metadata);
        if (!StringUtils.hasText(coverageLevel)
                && coverageScore == null
                && missingContexts.isEmpty()
                && !StringUtils.hasText(summary)
                && remediationHints.isEmpty()
                && !StringUtils.hasText(authenticationSource)
                && !StringUtils.hasText(authorizationSource)
                && !StringUtils.hasText(delegationSource)
                && evidenceStates.isEmpty()) {
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
                .evidenceStates(evidenceStates)
                .build();
    }

    /** The bridge's evidence state of each fact, by fact name (the metadata key without "EvidenceState"). */
    private Map<String, String> bridgeEvidenceStates(Map<String, Object> metadata) {
        Map<String, String> states = new LinkedHashMap<>();
        metadata.forEach((key, value) -> {
            String state = firstText(value);
            if (key.endsWith("EvidenceState") && key.length() > "EvidenceState".length() && state != null) {
                states.put(key.substring(0, key.length() - "EvidenceState".length()), state);
            }
        });
        String signalPurpose = firstText(metadata.get("privilegedAuthoritySignalPurpose"));
        if (signalPurpose != null) {
            states.put("privilegedAuthoritySignals", signalPurpose);
        }
        return states;
    }

    /**
     * The facts whose sources disagree, kept as facts: the aliases of a field that gave different values, the
     * authorization evidence the bridge settled, and an explicit handoff naming another principal.
     */
    private List<CanonicalSecurityContext.DataConflict> resolveDataConflicts(
            Map<String, Object> metadata, Map<String, Object> attributes) {
        List<CanonicalSecurityContext.DataConflict> conflicts = new ArrayList<>();
        if (attributes.get("canonicalConflicts") instanceof List<?> aliasConflicts) {
            for (Object item : aliasConflicts) {
                if (item instanceof Map<?, ?> conflict) {
                    Map<String, String> sources = new LinkedHashMap<>();
                    if (conflict.get("sources") instanceof Map<?, ?> values) {
                        values.forEach((source, value) -> sources.put(String.valueOf(source), String.valueOf(value)));
                    }
                    conflicts.add(CanonicalSecurityContext.DataConflict.builder()
                            .field(firstText(conflict.get("field")))
                            .sources(sources)
                            .selected(firstText(conflict.get("selected")))
                            .build());
                }
            }
        }
        if (Boolean.TRUE.equals(resolveBoolean(metadata.get("authorizationConflict")))) {
            Map<String, String> sources = new LinkedHashMap<>();
            for (String evidence : normalizeStrings(metadata.get("authorizationConflictEvidence"))) {
                int separator = evidence.lastIndexOf(':');
                if (separator > 0) {
                    sources.put(evidence.substring(0, separator), evidence.substring(separator + 1));
                }
            }
            conflicts.add(CanonicalSecurityContext.DataConflict.builder()
                    .field("authorization.authorizationEffect")
                    .sources(sources)
                    .selected(firstText(metadata.get("authorizationConflictSelected")))
                    .resolution(firstText(metadata.get("authorizationConflictResolution")))
                    .build());
        }
        if (Boolean.TRUE.equals(resolveBoolean(metadata.get("bridgeHandoffConflict")))) {
            Map<String, String> sources = new LinkedHashMap<>();
            String resolvedPrincipal = firstText(metadata.get("bridgeResolvedPrincipalId"));
            String handoffPrincipal = firstText(metadata.get("bridgeHandoffPrincipalId"));
            if (resolvedPrincipal != null) {
                sources.put("bridge.resolvedPrincipal", resolvedPrincipal);
            }
            if (handoffPrincipal != null) {
                sources.put("bridge.handoffPrincipal", handoffPrincipal);
            }
            conflicts.add(CanonicalSecurityContext.DataConflict.builder()
                    .field("actor.principalId")
                    .sources(sources)
                    .selected(resolvedPrincipal)
                    .build());
        }
        return conflicts;
    }

    private void enrichFromRegistry(CanonicalSecurityContext context) {
        // The resource the request names first, else the protected method it went through (W2-11).
        Object protectableResourceId = context.getAttributes() != null
                ? context.getAttributes().get("protectableResourceId") : null;
        resourceContextRegistry.findByEvent(context)
                .or(() -> resourceContextRegistry.findByResourceId(
                        protectableResourceId != null ? protectableResourceId.toString() : null))
                .ifPresent(descriptor -> {
            CanonicalSecurityContext.Resource resource = context.getResource();
            if (resource == null) {
                resource = new CanonicalSecurityContext.Resource();
                resource.setResourceId(descriptor.resourceId());
                context.setResource(resource);
            }
            if (!StringUtils.hasText(resource.getResourceType())) {
                resource.setResourceType(descriptor.resourceType());
            }
            if (!StringUtils.hasText(resource.getResourceCategory())) {
                resource.setResourceCategory(descriptor.resourceCategory());
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
            // What a protected method allows is not a permission scope the requester holds: the scope tags stay the
            // authorization's own (N-ID-1, Q-69).
        });
    }

    /**
     * The resource's two standard fields, once the registry and the providers have spoken: its class from the
     * classification values only, and its business category in the order the role scope collector reads it: the
     * official field, the unprefixed hints, the protected method's descriptor, the registry, then the type (W2-11).
     * A class word is never a category, and a category never decides the class.
     */
    private void classifyResource(CanonicalSecurityContext context, Map<String, Object> metadata) {
        CanonicalSecurityContext.Resource resource = context.getResource();
        if (resource == null) {
            return;
        }
        resource.setResourceClass(SecuritySemanticNormalizer.normalizeResourceClass(
                resource.getSensitivity(), resource.getResourceType()));
        resource.setResourceCategory(SecuritySemanticNormalizer.normalizeResourceCategory(
                metadata.get("resourceCategory"),
                metadata.get("currentResourceFamily"),
                metadata.get("current_resource_family"),
                metadata.get("resourceFamily"),
                metadata.get("protectableResourceCategory"),
                resource.getResourceCategory(),
                resource.getResourceType()));
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
            if (enricher == null) {
                continue;
            }
            try {
                enricher.enrich(event, context);
            } catch (Exception ex) {
                log.warn("Canonical context enricher {} failed for event {}: {}",
                        enricher.getClass().getSimpleName(),
                        event != null ? event.getEventId() : "unknown",
                        ex.getMessage(),
                        ex);
            }
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
}
