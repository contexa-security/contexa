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
    private final ObservedScopeInferenceService observedScopeInferenceService;
    private final CanonicalSecurityContextHardener contextHardener;

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator) {
        this(resourceContextRegistry, coverageEvaluator, List.of(), List.of(), List.of(), List.of(), new MetadataObservedScopeInferenceService(), new CanonicalSecurityContextHardener());
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
                organizationContextProviders, delegationContextProviders, observedScopeInferenceService, new CanonicalSecurityContextHardener());
    }

    public DefaultCanonicalSecurityContextProvider(
            ResourceContextRegistry resourceContextRegistry,
            ContextCoverageEvaluator coverageEvaluator,
            List<AuthenticationContextProvider> authenticationContextProviders,
            List<AuthorizationSnapshotProvider> authorizationSnapshotProviders,
            List<OrganizationContextProvider> organizationContextProviders,
            List<DelegationContextProvider> delegationContextProviders,
            ObservedScopeInferenceService observedScopeInferenceService,
            CanonicalSecurityContextHardener contextHardener) {
        this.resourceContextRegistry = resourceContextRegistry;
        this.coverageEvaluator = coverageEvaluator;
        this.authenticationContextProviders = authenticationContextProviders != null ? List.copyOf(authenticationContextProviders) : List.of();
        this.authorizationSnapshotProviders = authorizationSnapshotProviders != null ? List.copyOf(authorizationSnapshotProviders) : List.of();
        this.organizationContextProviders = organizationContextProviders != null ? List.copyOf(organizationContextProviders) : List.of();
        this.delegationContextProviders = delegationContextProviders != null ? List.copyOf(delegationContextProviders) : List.of();
        this.observedScopeInferenceService = observedScopeInferenceService;
        this.contextHardener = contextHardener != null ? contextHardener : new CanonicalSecurityContextHardener();
    }

    @Override
    public Optional<CanonicalSecurityContext> resolve(SecurityEvent event) {
        if (event == null) {
            return Optional.empty();
        }

        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();

        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(resolveActor(event, metadata))
                .session(resolveSession(event, metadata))
                .resource(resolveResource(event, metadata))
                .authorization(resolveAuthorization(metadata))
                .delegation(resolveDelegation(metadata))
                .attributes(new LinkedHashMap<>(metadata))
                .build();

        enrichFromRegistry(context);
        applyProviderContributions(event, context);
        inferObservedScope(event, context);
        contextHardener.harden(context);
        context.setCoverage(coverageEvaluator.evaluate(context));
        return Optional.of(context);
    }

    private CanonicalSecurityContext.Actor resolveActor(SecurityEvent event, Map<String, Object> metadata) {
        return CanonicalSecurityContext.Actor.builder()
                .userId(firstText(event.getUserId(), metadata.get("userId")))
                .organizationId(firstText(metadata.get("organizationId"), metadata.get("orgId"), metadata.get("tenantId")))
                .department(firstText(metadata.get("department"), metadata.get("team"), metadata.get("group")))
                .principalType(firstText(metadata.get("principalType"), metadata.get("principal.type"), metadata.get("userType")))
                .roleSet(normalizeStrings(metadata.get("userRoles"), metadata.get("roles"), metadata.get("roleSet")))
                .authoritySet(normalizeStrings(metadata.get("authorities"), metadata.get("permissions"), metadata.get("grantedAuthorities")))
                .build();
    }

    private CanonicalSecurityContext.Session resolveSession(SecurityEvent event, Map<String, Object> metadata) {
        return CanonicalSecurityContext.Session.builder()
                .sessionId(firstText(event.getSessionId(), metadata.get("sessionId")))
                .clientIp(firstText(event.getSourceIp(), metadata.get("clientIp")))
                .userAgent(firstText(event.getUserAgent(), metadata.get("userAgent")))
                .mfaVerified(resolveBoolean(metadata.get("mfaVerified"), metadata.get("mfa_verified")))
                .failedLoginAttempts(resolveInteger(metadata.get("failedLoginAttempts"), metadata.get("failed_login_attempts")))
                .recentRequestCount(resolveInteger(metadata.get("recentRequestCount"), metadata.get("recent_request_count")))
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
                .privileged(resolveBoolean(metadata.get("privileged"), metadata.get("isPrivileged")))
                .build();
    }

    private CanonicalSecurityContext.Delegation resolveDelegation(Map<String, Object> metadata) {
        return CanonicalSecurityContext.Delegation.builder()
                .agentId(firstText(metadata.get("agentId"), metadata.get("agent_id")))
                .objectiveId(firstText(metadata.get("objectiveId"), metadata.get("task_purpose")))
                .objectiveFamily(firstText(metadata.get("objectiveFamily"), metadata.get("objective_family")))
                .allowedOperations(normalizeStrings(metadata.get("allowedOperations"), metadata.get("allowed_operations")))
                .allowedResources(normalizeStrings(metadata.get("allowedResources"), metadata.get("allowed_resources"), metadata.get("allowedResourceFamilies")))
                .privilegedExportAllowed(resolveBoolean(metadata.get("privilegedExportAllowed"), metadata.get("privileged_export_allowed")))
                .containmentOnly(resolveBoolean(metadata.get("containmentOnly"), metadata.get("containment_only")))
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
    }

    private void inferObservedScope(SecurityEvent event, CanonicalSecurityContext context) {
        if (observedScopeInferenceService == null) {
            return;
        }
        observedScopeInferenceService.infer(event, context).ifPresent(context::setObservedScope);
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

    private List<String> copyList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(values);
    }
}
