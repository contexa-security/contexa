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
package io.contexa.contexaiam.admin.web.agent.service;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Records and revokes delegations for the delegation API, the admin API and the console (docs/agent OC-1), and audits
 * every change. A person records only their own delegations; an agent never records one (a delegation is the person's
 * word, OWASP ASI03, attack map AT-28): a token acting for a person ({@code act}), a client's own token and an agent's
 * own account are refused here, and any request the bridge stamped as an agent's by the delegation API.
 */
public class AgentDelegationService {

    /** Who may not record or revoke a delegation in their own name. */
    public static class AgentCallerException extends RuntimeException {
        public AgentCallerException() {
            super("An agent cannot record or revoke a delegation");
        }
    }

    private static final String ACT_CLAIM = "act";
    private static final String CLIENT_ID_CLAIM = "client_id";

    private final DelegationRegistry registry;
    private final AgentClientDirectory agents;
    private final CentralAuditFacade auditFacade;

    public AgentDelegationService(DelegationRegistry registry, @Nullable AgentClientDirectory agents,
                                  @Nullable CentralAuditFacade auditFacade) {
        this.registry = Objects.requireNonNull(registry, "A delegation registry is required");
        this.agents = agents != null ? agents : AgentClientDirectory.NONE;
        this.auditFacade = auditFacade;
    }

    /** The person's delegation in their own name, written by them now. */
    public AgentDelegation recordOwn(Authentication person, @Nullable String tenantId, AgentDelegationRequest request) {
        String delegator = requirePerson(person, tenantId);
        AgentDelegation recorded = registry.record(new AgentDelegationRequest(tenantId, delegator, request.agentId(),
                request.objectiveId(), request.objectiveFamily(), request.objectiveSummary(),
                request.allowedOperations(), request.allowedResources(), request.approvalRequired(),
                request.privilegedExportAllowed(), request.containmentOnly(), request.validFrom(), request.expiresAt(),
                delegator, null, request.maxItemsPerRequest(), request.maxItemsTotal()));
        audit(AuditEventCategory.AGENT_DELEGATION_RECORDED, delegator, recorded, null);
        return recorded;
    }

    /**
     * A delegation an administrator or an integration records for a person, as the application's records state it:
     * the writer and time stated, else the administrator now.
     */
    public AgentDelegation recordFor(String administrator, AgentDelegationRequest request) {
        AgentDelegation recorded = registry.record(new AgentDelegationRequest(request.tenantId(),
                request.delegatorId(), request.agentId(), request.objectiveId(), request.objectiveFamily(),
                request.objectiveSummary(), request.allowedOperations(), request.allowedResources(),
                request.approvalRequired(), request.privilegedExportAllowed(), request.containmentOnly(),
                request.validFrom(), request.expiresAt(),
                request.recordedBy() != null && !request.recordedBy().isBlank() ? request.recordedBy() : administrator,
                request.recordedAt(), request.maxItemsPerRequest(), request.maxItemsTotal()));
        audit(AuditEventCategory.AGENT_DELEGATION_RECORDED, administrator, recorded, null);
        return recorded;
    }

    /** The person's own delegations, latest first. */
    public List<AgentDelegation> listOwn(Authentication person, @Nullable String tenantId, int limit) {
        return registry.list(tenantId, requirePerson(person, tenantId), null, limit);
    }

    /** Delegations for the console and the admin API. */
    public List<AgentDelegation> list(@Nullable String tenantId, @Nullable String delegatorId, @Nullable String agentId,
                                      int limit) {
        return registry.list(tenantId, delegatorId, agentId, limit);
    }

    /** Revokes the person's own delegation; empty when it is not theirs or unknown. */
    public Optional<AgentDelegation> revokeOwn(Authentication person, @Nullable String tenantId, String delegationId,
                                               @Nullable String reason) {
        String delegator = requirePerson(person, tenantId);
        Optional<AgentDelegation> own = registry.find(delegationId)
                .filter(delegation -> delegator.equals(delegation.delegatorId()));
        if (own.isEmpty()) {
            return Optional.empty();
        }
        return revoke(delegator, delegationId, reason);
    }

    /** Revokes a delegation as an administrator; a reason is required. */
    public Optional<AgentDelegation> revokeAsAdministrator(String administrator, String delegationId, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("A reason is required");
        }
        return revoke(administrator, delegationId, reason.trim());
    }

    /** Whether the caller is an agent and so may not record or revoke in its own name. */
    public boolean agentCaller(@Nullable Authentication authentication, @Nullable String tenantId) {
        if (authentication == null) {
            return false;
        }
        Map<String, Object> claims = OAuth2AuthenticationSupport.tokenClaims(authentication);
        if (claims.get(ACT_CLAIM) != null) {
            return true;
        }
        Object client = claims.get(CLIENT_ID_CLAIM);
        if (client != null && client.equals(claims.get("sub"))) {
            return true;
        }
        String name = authentication.getName();
        return name != null && agents.activeAgentForAccount(tenantId, name).isPresent();
    }

    private Optional<AgentDelegation> revoke(String actor, String delegationId, @Nullable String reason) {
        Optional<AgentDelegation> revoked = registry.revoke(delegationId, actor, reason);
        revoked.ifPresent(delegation -> audit(AuditEventCategory.AGENT_DELEGATION_REVOKED, actor, delegation, reason));
        return revoked;
    }

    private String requirePerson(Authentication person, @Nullable String tenantId) {
        if (person == null || person.getName() == null || person.getName().isBlank()) {
            throw new IllegalStateException("No person is signed in");
        }
        if (agentCaller(person, tenantId)) {
            throw new AgentCallerException();
        }
        return person.getName();
    }

    private void audit(AuditEventCategory category, String actor, AgentDelegation delegation, @Nullable String reason) {
        if (auditFacade == null) {
            return;
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("delegationId", delegation.delegationId());
        details.put("delegatorId", delegation.delegatorId());
        details.put("agentId", delegation.agentId());
        details.put("tenantId", delegation.tenantId() != null ? delegation.tenantId() : "");
        details.put("allowedOperations", delegation.allowedOperations());
        details.put("allowedResources", delegation.allowedResources());
        details.put("validFrom", String.valueOf(delegation.validFrom()));
        details.put("expiresAt", String.valueOf(delegation.expiresAt()));
        auditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(category)
                .principalName(actor)
                .resourceIdentifier(delegation.agentId())
                .eventSource("IAM")
                .action(category.name())
                .outcome(category == AuditEventCategory.AGENT_DELEGATION_REVOKED ? "REVOKED" : "RECORDED")
                .reason(reason)
                .details(details)
                .build());
    }
}
