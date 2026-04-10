package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.execution.AttestationEnvelope;
import io.contexa.contexacore.autonomous.execution.CanonicalExecutionBinding;
import io.contexa.contexacore.autonomous.execution.CanonicalExecutionMapper;
import io.contexa.contexacore.autonomous.execution.ExecutionEnvelope;
import io.contexa.contexacore.autonomous.execution.ExecutionProvenance;
import io.contexa.contexacore.autonomous.execution.ExecutionProtocolTypes;
import io.contexa.contexacore.autonomous.execution.ExecutionSubject;
import io.contexa.contexacore.autonomous.execution.ExecutionSubjectTypes;
import io.contexa.contexacore.autonomous.execution.DelegatedExecutionContext;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CanonicalExecutionContextResolver {

    private final CanonicalExecutionMapper canonicalExecutionMapper;

    public CanonicalExecutionContextResolver() {
        this(new CanonicalExecutionMapper());
    }

    public CanonicalExecutionContextResolver(CanonicalExecutionMapper canonicalExecutionMapper) {
        this.canonicalExecutionMapper = canonicalExecutionMapper != null ? canonicalExecutionMapper : new CanonicalExecutionMapper();
    }

    public ExecutionSubject resolveSubject(CanonicalSecurityContext context) {
        CanonicalExecutionBinding binding = resolveBinding(context);
        return binding != null ? binding.executionSubject() : null;
    }

    public ExecutionEnvelope resolveEnvelope(CanonicalSecurityContext context) {
        CanonicalExecutionBinding binding = resolveBinding(context);
        return binding != null ? binding.executionEnvelope() : null;
    }

    public CanonicalExecutionBinding resolveBinding(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }
        Map<String, Object> attributes = context.getAttributes() != null ? context.getAttributes() : Map.of();
        CanonicalSecurityContext.Actor actor = context.getActor();
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        boolean serviceClientPrincipal = isServiceClientPrincipal(actor, attributes);
        String tenantId = firstText(
                actor != null ? actor.getTenantId() : null,
                actor != null ? actor.getOrganizationId() : null,
                text(attributes.get("tenantId")),
                text(attributes.get("tenant_id")),
                text(attributes.get("organizationId")));
        String clientId = firstText(text(attributes.get("clientId")), text(attributes.get("client_id")), actor != null ? actor.getExternalSubjectId() : null);
        DelegatedExecutionContext delegatedExecutionContext = toDelegatedExecutionContext(context, clientId);
        CanonicalExecutionBinding binding = canonicalExecutionMapper.toCanonical(tenantId, clientId, serviceClientPrincipal, delegatedExecutionContext);
        ExecutionSubject subject = overrideSubject(binding.executionSubject(), actor, tenantId, clientId, serviceClientPrincipal, delegatedExecutionContext);
        ExecutionEnvelope envelope = overrideEnvelope(binding.executionEnvelope(), attributes, serviceClientPrincipal);
        return new CanonicalExecutionBinding(subject, envelope);
    }

    private ExecutionSubject overrideSubject(
            ExecutionSubject subject,
            CanonicalSecurityContext.Actor actor,
            String tenantId,
            String clientId,
            boolean serviceClientPrincipal,
            DelegatedExecutionContext delegatedExecutionContext) {
        if (subject == null) {
            return canonicalExecutionMapper.toSubject(tenantId, clientId, serviceClientPrincipal, delegatedExecutionContext);
        }
        String subjectType = subject.subjectType();
        if (!StringUtils.hasText(subjectType)) {
            subjectType = serviceClientPrincipal
                    ? ExecutionSubjectTypes.SERVICE_CLIENT
                    : (delegatedExecutionContext != null && delegatedExecutionContext.delegatedAgentExecution()
                    ? ExecutionSubjectTypes.AGENT_RUNTIME
                    : ExecutionSubjectTypes.HUMAN_USER);
        }
        return new ExecutionSubject(
                subjectType,
                firstText(subject.actorUserId(), actor != null ? actor.getUserId() : null, delegatedExecutionContext != null ? delegatedExecutionContext.actorUserId() : null),
                firstText(subject.tenantId(), tenantId),
                firstText(subject.externalSubjectId(), actor != null ? actor.getExternalSubjectId() : null, clientId),
                firstText(subject.principalType(), actor != null ? actor.getPrincipalType() : null, serviceClientPrincipal ? "SERVICE_CLIENT" : subjectType),
                subject.humanProfile(),
                subject.serviceClientProfile(),
                subject.delegatedAgentProfile());
    }

    private ExecutionEnvelope overrideEnvelope(ExecutionEnvelope envelope, Map<String, Object> attributes, boolean serviceClientPrincipal) {
        if (envelope == null) {
            return null;
        }
        ExecutionProvenance currentProvenance = envelope.provenance();
        String protocolType = firstText(
                text(attributes.get("executionProtocolType")),
                text(attributes.get("protocolType")),
                text(attributes.get("sourceProtocol")),
                currentProvenance != null ? currentProvenance.protocolType() : null,
                serviceClientPrincipal ? ExecutionProtocolTypes.INTERNAL_RUNTIME : ExecutionProtocolTypes.HUMAN_SESSION);
        String protocolVersion = firstText(
                text(attributes.get("executionProtocolVersion")),
                text(attributes.get("protocolVersion")),
                currentProvenance != null ? currentProvenance.protocolVersion() : null);
        String chainId = firstText(text(attributes.get("chainId")), text(attributes.get("executionId")), envelope.executionId(), envelope.delegationId());
        Integer chainDepth = resolveInteger(attributes.get("chainDepth"));
        if (chainDepth == null) {
            chainDepth = envelope.parentExecutionId() != null ? 1 : 0;
        }
        AttestationEnvelope attestationEnvelope = new AttestationEnvelope(
                firstText(text(attributes.get("attestationState")), text(attributes.get("agentAttestationState"))),
                firstText(text(attributes.get("runtimePostureState")), text(attributes.get("agentRuntimePostureState"))),
                firstText(text(attributes.get("trustTier")), text(attributes.get("agentTrustTier"))),
                Map.of());
        ExecutionProvenance provenance = new ExecutionProvenance(
                protocolType,
                protocolVersion,
                currentProvenance != null ? currentProvenance.sourceSystem() : null,
                firstText(text(attributes.get("sourceReference")), currentProvenance != null ? currentProvenance.sourceReference() : null, envelope.executionId()),
                chainId,
                chainDepth,
                envelope.lineageState(),
                serviceClientPrincipal,
                currentProvenance != null ? currentProvenance.observedAt() : LocalDateTime.now(),
                currentProvenance != null ? currentProvenance.attributes() : Map.of());
        return new ExecutionEnvelope(
                envelope.delegatedExecutionContext(),
                envelope.objectiveDescriptor(),
                envelope.authorizationBoundary(),
                envelope.permitBinding(),
                envelope.approvalBinding(),
                envelope.executionWindow(),
                attestationEnvelope,
                provenance);
    }

    private DelegatedExecutionContext toDelegatedExecutionContext(CanonicalSecurityContext context, String clientId) {
        Map<String, Object> attributes = context.getAttributes() != null ? context.getAttributes() : Map.of();
        CanonicalSecurityContext.Actor actor = context.getActor();
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        String executionMode = firstText(
                text(attributes.get("executionMode")),
                delegation != null && Boolean.TRUE.equals(delegation.getDelegated())
                        ? DelegatedExecutionContext.EXECUTION_MODE_DELEGATED_AGENT
                        : DelegatedExecutionContext.EXECUTION_MODE_DIRECT_USER);
        String lineageState = firstText(
                text(attributes.get("lineageState")),
                delegation != null && Boolean.TRUE.equals(delegation.getDelegated())
                        ? DelegatedExecutionContext.LINEAGE_STATE_DECLARED
                        : DelegatedExecutionContext.LINEAGE_STATE_DIRECT);
        return new DelegatedExecutionContext(
                firstText(text(attributes.get("executionId")), text(attributes.get("requestId"))),
                executionMode,
                lineageState,
                firstText(actor != null ? actor.getUserId() : null, text(attributes.get("actorUserId"))),
                firstText(delegation != null ? delegation.getAgentId() : null, text(attributes.get("agentId"))),
                firstText(text(attributes.get("agentRuntimeId")), text(attributes.get("clientId"))),
                firstText(text(attributes.get("delegationId"))),
                firstText(text(attributes.get("parentExecutionId"))),
                firstText(text(attributes.get("taskIntent")), text(attributes.get("task_intent"))),
                firstText(text(attributes.get("taskPurpose")), delegation != null ? delegation.getObjectiveSummary() : null, delegation != null ? delegation.getObjectiveId() : null),
                normalizeList(attributes.get("requestedScopes")),
                normalizeList(attributes.get("approvedScopes")),
                normalizeList(attributes.get("toolChain")),
                firstText(text(attributes.get("permitId"))),
                firstText(text(attributes.get("approvalId"))),
                resolveDateTime(attributes.get("startedAt")),
                resolveDateTime(attributes.get("expiresAt")),
                firstText(text(attributes.get("objectiveId")), delegation != null ? delegation.getObjectiveId() : null),
                firstText(text(attributes.get("objectiveFamily")), delegation != null ? delegation.getObjectiveFamily() : null),
                normalizeList(attributes.get("allowedResourceFamilies"), delegation != null ? delegation.getAllowedResources() : List.of()),
                normalizeList(attributes.get("allowedOperations"), delegation != null ? delegation.getAllowedOperations() : List.of()),
                normalizeList(attributes.get("allowedToolChain")),
                Boolean.TRUE.equals(delegation != null ? delegation.getContainmentOnly() : resolveBoolean(attributes.get("containmentOnly"))),
                Boolean.TRUE.equals(delegation != null ? delegation.getPrivilegedExportAllowed() : resolveBoolean(attributes.get("privilegedExportAllowed"))));
    }

    private boolean isServiceClientPrincipal(CanonicalSecurityContext.Actor actor, Map<String, Object> attributes) {
        String principalType = firstText(actor != null ? actor.getPrincipalType() : null, text(attributes.get("principalType")));
        if (StringUtils.hasText(principalType)) {
            String normalized = principalType.trim().toUpperCase();
            if (normalized.contains("SERVICE") || normalized.contains("CLIENT") || normalized.contains("WORKLOAD")) {
                return true;
            }
        }
        return Boolean.TRUE.equals(resolveBoolean(attributes.get("serviceClientPrincipal")));
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private List<String> normalizeList(Object... values) {
        java.util.LinkedHashSet<String> normalized = new java.util.LinkedHashSet<>();
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            if (value instanceof Iterable<?> iterable) {
                for (Object item : iterable) {
                    String text = text(item);
                    if (StringUtils.hasText(text)) {
                        normalized.add(text);
                    }
                }
            }
            else {
                String text = text(value);
                if (StringUtils.hasText(text)) {
                    for (String token : text.split("[,\\s]+")) {
                        if (StringUtils.hasText(token)) {
                            normalized.add(token.trim());
                        }
                    }
                }
            }
        }
        return List.copyOf(normalized);
    }

    private LocalDateTime resolveDateTime(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof LocalDateTime localDateTime) {
            return localDateTime;
        }
        if (value instanceof Instant instant) {
            return LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
        }
        String text = text(value);
        if (!StringUtils.hasText(text)) {
            return null;
        }
        try {
            return LocalDateTime.parse(text);
        }
        catch (RuntimeException ignored) {
            return null;
        }
    }

    private Integer resolveInteger(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        String text = text(value);
        if (!StringUtils.hasText(text)) {
            return null;
        }
        try {
            return Integer.parseInt(text);
        }
        catch (NumberFormatException ignored) {
            return null;
        }
    }

    private Boolean resolveBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        String text = text(value);
        return StringUtils.hasText(text) ? Boolean.parseBoolean(text) : null;
    }
}