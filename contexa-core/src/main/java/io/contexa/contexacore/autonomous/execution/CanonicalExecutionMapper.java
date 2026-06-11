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
package io.contexa.contexacore.autonomous.execution;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class CanonicalExecutionMapper {

    public CanonicalExecutionBinding toCanonical(
            String tenantId,
            String clientId,
            boolean serviceClientPrincipal,
            DelegatedExecutionContext context) {
        DelegatedExecutionContext effectiveContext = context != null
                ? context
                : (serviceClientPrincipal
                ? DelegatedExecutionContext.imputedServiceClient(null, clientId, List.of())
                : DelegatedExecutionContext.directUser(clientId));
        ExecutionSubject subject = toSubject(tenantId, clientId, serviceClientPrincipal, effectiveContext);
        ExecutionEnvelope envelope = toEnvelope(clientId, serviceClientPrincipal, effectiveContext, null, null);
        return new CanonicalExecutionBinding(subject, envelope);
    }

    public ExecutionSubject toSubject(
            String tenantId,
            String clientId,
            boolean serviceClientPrincipal,
            DelegatedExecutionContext context) {
        DelegatedExecutionContext effectiveContext = context != null ? context : DelegatedExecutionContext.directUser(clientId);
        String subjectType;
        HumanSubjectProfile humanProfile = null;
        ServiceClientSubjectProfile serviceClientProfile = null;
        DelegatedAgentProfile delegatedAgentProfile = null;
        if (serviceClientPrincipal) {
            subjectType = ExecutionSubjectTypes.SERVICE_CLIENT;
            serviceClientProfile = new ServiceClientSubjectProfile(
                    clientId,
                    effectiveContext.declaredLineage() ? "DELEGATED_RUNTIME" : "INTERNAL_SERVICE_CLIENT",
                    true,
                    "TENANT_SERVICE_CLIENT",
                    effectiveContext.approvedScopes());
        }
        else if (effectiveContext.delegatedAgentExecution() || hasText(effectiveContext.agentId()) || hasText(effectiveContext.delegationId())) {
            subjectType = ExecutionSubjectTypes.AGENT_RUNTIME;
            delegatedAgentProfile = new DelegatedAgentProfile(
                    effectiveContext.agentId(),
                    effectiveContext.agentRuntimeId(),
                    effectiveContext.delegationId(),
                    effectiveContext.parentExecutionId(),
                    "DELEGATED_AGENT",
                    null,
                    null,
                    effectiveContext.allowedToolChain());
        }
        else {
            subjectType = ExecutionSubjectTypes.HUMAN_USER;
            humanProfile = new HumanSubjectProfile(
                    effectiveContext.actorUserId(),
                    null,
                    tenantId,
                    null,
                    null,
                    List.of(),
                    List.of());
        }
        return new ExecutionSubject(
                subjectType,
                effectiveContext.actorUserId(),
                tenantId,
                hasText(effectiveContext.actorUserId()) ? effectiveContext.actorUserId() : clientId,
                serviceClientPrincipal ? "SERVICE_CLIENT" : subjectType,
                humanProfile,
                serviceClientProfile,
                delegatedAgentProfile);
    }

    public ExecutionEnvelope toEnvelope(
            String clientId,
            boolean serviceClientPrincipal,
            DelegatedExecutionContext context,
            String protocolType,
            String protocolVersion) {
        DelegatedExecutionContext effectiveContext = context != null ? context : DelegatedExecutionContext.directUser(clientId);
        ObjectiveDescriptor objectiveDescriptor = new ObjectiveDescriptor(
                effectiveContext.taskIntent(),
                effectiveContext.taskPurpose(),
                effectiveContext.objectiveId(),
                effectiveContext.objectiveFamily(),
                effectiveContext.taskPurpose());
        AuthorizationBoundary authorizationBoundary = new AuthorizationBoundary(
                effectiveContext.requestedScopes(),
                effectiveContext.approvedScopes(),
                effectiveContext.allowedOperations(),
                effectiveContext.allowedResourceFamilies(),
                effectiveContext.allowedToolChain(),
                effectiveContext.containmentOnly(),
                effectiveContext.privilegedExportAllowed());
        PermitBinding permitBinding = new PermitBinding(effectiveContext.permitId(), null);
        ApprovalBinding approvalBinding = new ApprovalBinding(effectiveContext.approvalId(), effectiveContext.delegatedAgentExecution(), null);
        ExecutionWindow executionWindow = new ExecutionWindow(effectiveContext.startedAt(), effectiveContext.expiresAt());
        AttestationEnvelope attestationEnvelope = new AttestationEnvelope(null, null, null, Map.of());
        String effectiveProtocolType = hasText(protocolType)
                ? protocolType
                : defaultProtocolType(serviceClientPrincipal, effectiveContext);
        ExecutionProvenance provenance = new ExecutionProvenance(
                effectiveProtocolType,
                protocolVersion,
                serviceClientPrincipal ? "SERVICE_CLIENT_RUNTIME" : "INTERACTIVE_RUNTIME",
                effectiveContext.executionId(),
                hasText(effectiveContext.executionId()) ? effectiveContext.executionId() : effectiveContext.delegationId(),
                effectiveContext.parentExecutionId() != null ? 1 : 0,
                effectiveContext.lineageState(),
                serviceClientPrincipal,
                effectiveContext.startedAt() != null ? effectiveContext.startedAt() : LocalDateTime.now(),
                defaultProvenanceAttributes(effectiveContext));
        return new ExecutionEnvelope(
                effectiveContext,
                objectiveDescriptor,
                authorizationBoundary,
                permitBinding,
                approvalBinding,
                executionWindow,
                attestationEnvelope,
                provenance);
    }

    public ExecutionPolicyView toPolicyView(
            String tenantId,
            String clientId,
            boolean serviceClientPrincipal,
            ExecutionSubject subject,
            ExecutionEnvelope envelope) {
        DelegatedExecutionContext context = envelope != null ? envelope.delegatedExecutionContext() : null;
        String summary = String.format(Locale.ROOT,
                "%s subject executing objective %s via %s.",
                subject != null && hasText(subject.subjectType()) ? subject.subjectType() : ExecutionSubjectTypes.UNKNOWN,
                envelope != null && envelope.objectiveDescriptor() != null && hasText(envelope.objectiveDescriptor().objectiveFamily())
                        ? envelope.objectiveDescriptor().objectiveFamily()
                        : "UNSPECIFIED_OBJECTIVE",
                envelope != null && envelope.provenance() != null && hasText(envelope.provenance().protocolType())
                        ? envelope.provenance().protocolType()
                        : ExecutionProtocolTypes.UNKNOWN);
        return new ExecutionPolicyView(
                tenantId,
                clientId,
                subject != null ? subject.subjectType() : ExecutionSubjectTypes.UNKNOWN,
                serviceClientPrincipal,
                context != null ? context.executionMode() : null,
                context != null ? context.lineageState() : null,
                context != null ? context.actorUserId() : null,
                context != null ? context.agentId() : null,
                context != null ? context.delegationId() : null,
                context != null ? context.taskIntent() : null,
                context != null ? context.taskPurpose() : null,
                context != null ? context.objectiveId() : null,
                context != null ? context.objectiveFamily() : null,
                context != null ? context.allowedResourceFamilies() : List.of(),
                context != null ? context.allowedOperations() : List.of(),
                context != null ? context.allowedToolChain() : List.of(),
                context != null && context.containmentOnly(),
                context != null && context.privilegedExportAllowed(),
                context != null ? context.approvedScopes() : List.of(),
                context != null ? context.toolChain() : List.of(),
                context != null ? context.permitId() : null,
                context != null ? context.approvalId() : null,
                envelope != null && envelope.provenance() != null ? envelope.provenance().protocolType() : ExecutionProtocolTypes.UNKNOWN,
                envelope != null && envelope.provenance() != null ? envelope.provenance().protocolVersion() : null,
                envelope != null && envelope.provenance() != null ? envelope.provenance().chainId() : null,
                envelope != null && envelope.provenance() != null ? envelope.provenance().chainDepth() : null,
                envelope != null && envelope.attestationEnvelope() != null ? envelope.attestationEnvelope().attestationState() : null,
                context != null ? context.startedAt() : null,
                context != null ? context.expiresAt() : null,
                summary);
    }

    public DelegatedExecutionContext toDelegatedExecutionContext(ExecutionEnvelope envelope) {
        if (envelope == null) {
            return null;
        }
        if (envelope.delegatedExecutionContext() != null) {
            return envelope.delegatedExecutionContext();
        }
        ObjectiveDescriptor objectiveDescriptor = envelope.objectiveDescriptor();
        AuthorizationBoundary boundary = envelope.authorizationBoundary();
        PermitBinding permitBinding = envelope.permitBinding();
        ApprovalBinding approvalBinding = envelope.approvalBinding();
        ExecutionWindow executionWindow = envelope.executionWindow();
        return new DelegatedExecutionContext(
                envelope.executionId(),
                null,
                envelope.lineageState(),
                null,
                envelope.agentId(),
                null,
                envelope.delegationId(),
                envelope.parentExecutionId(),
                objectiveDescriptor != null ? objectiveDescriptor.taskIntent() : null,
                objectiveDescriptor != null ? objectiveDescriptor.taskPurpose() : null,
                boundary != null ? boundary.requestedScopes() : List.of(),
                boundary != null ? boundary.approvedScopes() : List.of(),
                boundary != null ? boundary.allowedToolChain() : List.of(),
                permitBinding != null ? permitBinding.permitId() : null,
                approvalBinding != null ? approvalBinding.approvalId() : null,
                executionWindow != null ? executionWindow.startedAt() : null,
                executionWindow != null ? executionWindow.expiresAt() : null,
                objectiveDescriptor != null ? objectiveDescriptor.objectiveId() : null,
                objectiveDescriptor != null ? objectiveDescriptor.objectiveFamily() : null,
                boundary != null ? boundary.allowedResourceFamilies() : List.of(),
                boundary != null ? boundary.allowedOperations() : List.of(),
                boundary != null ? boundary.allowedToolChain() : List.of(),
                boundary != null && boundary.containmentOnly(),
                boundary != null && boundary.privilegedExportAllowed());
    }

    private String defaultProtocolType(boolean serviceClientPrincipal, DelegatedExecutionContext context) {
        if (!serviceClientPrincipal && context != null && context.directUserExecution()) {
            return ExecutionProtocolTypes.HUMAN_SESSION;
        }
        return serviceClientPrincipal ? ExecutionProtocolTypes.INTERNAL_RUNTIME : ExecutionProtocolTypes.UNKNOWN;
    }

    private Map<String, Object> defaultProvenanceAttributes(DelegatedExecutionContext context) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        putIfNotNull(attributes, "executionMode", context.executionMode());
        putIfNotNull(attributes, "lineageState", context.lineageState());
        putIfNotNull(attributes, "objectiveFamily", context.objectiveFamily());
        putIfNotNull(attributes, "approvedScopes", context.approvedScopes());
        return attributes;
    }

    private void putIfNotNull(Map<String, Object> attributes, String key, Object value) {
        if (value == null) {
            return;
        }
        if (value instanceof List<?> list && list.isEmpty()) {
            return;
        }
        attributes.put(key, value);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
