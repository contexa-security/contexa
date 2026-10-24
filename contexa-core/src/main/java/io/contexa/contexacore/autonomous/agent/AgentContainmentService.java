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
package io.contexa.contexacore.autonomous.agent;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Stops an agent and releases it (docs/agent A5-3, AG-6, OWASP ASI10 #4). A BLOCK on an agent's request stops that
 * agent only: acting for a person, its block is kept under its own key (A5-1), the delegation it ran under is revoked,
 * the tokens its client holds for that person are revoked and the person is told; acting on its own, its registration
 * is suspended (every token issued to it is refused) and its tokens are revoked, and its sponsor is told. The person's
 * own work goes on. An administrator releases a stopped agent; the kill switch stops or releases every agent of a type
 * or a tenant at once.
 */
@Slf4j
public class AgentContainmentService {

    /** The event metadata the steps taken on a BLOCK are written under, for the decision record (A5-5). */
    public static final String CONTAINMENT = "agentContainment";
    /** Who revokes a delegation a decision stopped. */
    public static final String REVOKED_BY = "contexa";
    /** The reason prefix of a suspension the kill switch made, so that its release resumes those agents only. */
    public static final String KILL_SWITCH_REASON = "KILL_SWITCH: ";
    static final int KILL_SWITCH_SCOPE = 10_000;

    private final ZeroTrustActionRepository actions;
    private final AgentRegistry registry;
    private final DelegationRegistry delegations;
    private final AgentTokenRevoker revoker;
    private final AgentNotices notices;
    private final CentralAuditFacade audit;

    public AgentContainmentService(ZeroTrustActionRepository actions, @Nullable AgentRegistry registry,
                                   @Nullable DelegationRegistry delegations, @Nullable AgentTokenRevoker revoker,
                                   @Nullable AgentNotices notices, @Nullable CentralAuditFacade audit) {
        this.actions = Objects.requireNonNull(actions, "actions");
        this.registry = registry;
        this.delegations = delegations;
        this.revoker = revoker;
        this.notices = notices;
        this.audit = audit;
    }

    /**
     * A BLOCK decided on the event's request. Nothing for a person's request.
     *
     * @return the steps taken, in order, for the decision record
     */
    public List<String> onBlock(SecurityEvent event, @Nullable String reason) {
        ZeroTrustSubject subject = ZeroTrustSubject.of(event);
        if (subject == null || subject.agentId() == null) {
            return List.of();
        }
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        Object stated = metadata.get(CredentialFacts.CLIENT_ID);
        return onBlock(subject, stated != null ? stated.toString() : null,
                accountable(metadata, subject.delegatedAgent() ? subject.userId() : null), reason,
                correlation(metadata));
    }

    /**
     * A BLOCK on a request of the subject (an agent's), outside the decision pipeline as well (an escalation promoted
     * to a block at the request). Nothing for a person.
     *
     * @param clientId      the agent's client as the request's credential names it, or null to read the registration
     * @param accountable   the person accountable for the request (A1-6), or null
     * @param correlationId the request the block is about, or null
     * @return the steps taken, in order, for the decision record
     */
    public List<String> onBlock(ZeroTrustSubject subject, @Nullable String clientId, @Nullable String accountable,
                                @Nullable String reason, @Nullable String correlationId) {
        if (subject == null || subject.agentId() == null) {
            return List.of();
        }
        String agentId = subject.agentId();
        String tenantId = subject.tenantId();
        Optional<AgentRegistration> registration = registration(tenantId, agentId);
        String client = StringUtils.hasText(clientId) ? clientId.trim()
                : registration.map(AgentRegistration::clientId).filter(StringUtils::hasText).orElse(null);
        String why = StringUtils.hasText(reason) ? reason.trim() : "a security decision stopped the agent";
        List<String> steps = new ArrayList<>();
        if (subject.delegatedAgent()) {
            revokeDelegation(subject.delegationId(), why).ifPresent(steps::add);
            if (client != null) {
                revokeTokens(subject.userId(), client).ifPresent(steps::add);
            }
            notifyStop(tenantId, StringUtils.hasText(accountable) ? accountable : subject.userId(), agentId,
                    subject.delegationId(), "The agent " + agentId + " was stopped while it worked for you",
                    "Contexa stopped the agent " + agentId + " acting for you: " + why + ". Its delegation was revoked "
                            + "and the tokens it held for you were revoked. Your own work is not affected. Delegate "
                            + "again once the agent is trusted.", correlationId, "DELEGATOR_NOTIFIED")
                    .ifPresent(steps::add);
        } else {
            // CF-13: the registration found may be the single-tenant one; it is suspended where it is kept.
            suspend(registration.isPresent() ? registration.get().tenantId() : tenantId, agentId, "BLOCK: " + why)
                    .ifPresent(steps::add);
            if (client != null) {
                revokeTokens(client, client).ifPresent(steps::add);
            }
            String sponsor = StringUtils.hasText(accountable) ? accountable
                    : registration.map(AgentRegistration::sponsorId).filter(StringUtils::hasText).orElse(null);
            notifyStop(tenantId, sponsor, agentId, null,
                    "The agent " + agentId + " you are accountable for was suspended",
                    "Contexa suspended the agent " + agentId + ": " + why + ". Every token issued to it is refused "
                            + "until an administrator releases it.", correlationId, "SPONSOR_NOTIFIED")
                    .ifPresent(steps::add);
        }
        record(AuditEventCategory.AGENT_STOPPED, REVOKED_BY, agentId, "AGENT_STOPPED", why, subject.kind().name(),
                subject.delegatedAgent() ? subject.userId() : null, subject.delegationId(), tenantId,
                Map.of("user", subject.userId(), "steps", String.join(", ", steps), "correlationId",
                        Objects.toString(correlationId, "")));
        return steps;
    }

    /**
     * The accountable person reported a request of the agent (docs/agent A5-2, AG-11k): the agent is stopped as a BLOCK
     * stops it, and a BLOCK is kept under its decision key at once, so its next request is refused before any
     * decision is made again.
     *
     * @return the steps taken, in order
     */
    public List<String> onReport(ZeroTrustSubject subject, String reportedBy, @Nullable String note,
                                 @Nullable String correlationId) {
        if (subject == null || subject.agentId() == null) {
            return List.of();
        }
        String why = "Reported by " + reportedBy + (StringUtils.hasText(note) ? ": " + note.trim() : "");
        List<String> steps = new ArrayList<>();
        try {
            actions.saveAction(subject.storageKey(), ZeroTrustAction.BLOCK, Map.of("reason", why));
            steps.add("AGENT_BLOCKED");
        } catch (RuntimeException e) {
            log.error("Keeping the reported agent's BLOCK failed: agentId={}", subject.agentId(), e);
            steps.add("AGENT_BLOCK_FAILED");
        }
        steps.addAll(onBlock(subject, null, reportedBy, why, correlationId));
        return steps;
    }

    /**
     * Releases an agent stopped while it acted for the person: its decisions for the person are cleared, so its next
     * request is decided again. The revoked delegation stays revoked: the person delegates again.
     */
    public void releaseDelegatedAgent(String userId, String agentId, String releasedBy, String reason) {
        requireText(userId, "userId");
        requireText(agentId, "agentId");
        actions.removeAllUserData(LearningSubject.agentKey(userId.trim(), agentId.trim()));
        record(AuditEventCategory.AGENT_RELEASED, releasedBy, agentId.trim(), "AGENT_RELEASED", reason,
                "DELEGATED_AGENT", userId.trim(), null, null, Map.of("scope", "DELEGATED"));
    }

    /**
     * Releases an agent suspended on its own: its registration is resumed and its own decisions are cleared.
     *
     * @return whether the registry knew the agent
     */
    public boolean releaseAgent(@Nullable String tenantId, String agentId, String releasedBy, String reason) {
        requireText(agentId, "agentId");
        Optional<AgentRegistration> resumed = registry != null
                ? registry.resume(tenantId, agentId.trim(), "RELEASED: " + Objects.toString(reason, ""))
                : Optional.empty();
        actions.removeAllUserData(agentId.trim());
        resumed.map(AgentRegistration::clientId).filter(StringUtils::hasText).ifPresent(actions::removeAllUserData);
        record(AuditEventCategory.AGENT_RELEASED, releasedBy, agentId.trim(), "AGENT_RELEASED", reason,
                "AUTONOMOUS_AGENT", null, null, tenantId, Map.of("scope", "AGENT",
                        "known", String.valueOf(resumed.isPresent())));
        return resumed.isPresent();
    }

    /**
     * The kill switch: suspends every agent in service of the type (every type for blank) in the tenant (every
     * tenant's for {@code null}).
     *
     * @return the agents suspended
     */
    public List<String> killSwitch(@Nullable String tenantId, @Nullable String agentType, String by, String reason) {
        List<String> stopped = new ArrayList<>();
        for (AgentRegistration agent : scope(tenantId, agentType)) {
            if (agent.status() != AgentStatus.ACTIVE) {
                continue;
            }
            registry.suspend(agent.tenantId(), agent.agentId(), KILL_SWITCH_REASON + Objects.toString(reason, ""))
                    .ifPresent(suspended -> stopped.add(suspended.agentId()));
        }
        record(AuditEventCategory.AGENT_KILL_SWITCH, by, Objects.toString(agentType, "*"), "KILL_SWITCH_ON", reason,
                null, null, null, tenantId, Map.of("agents", String.join(", ", stopped)));
        return stopped;
    }

    /** Releases the agents the kill switch suspended in that scope; agents stopped otherwise stay stopped. */
    public List<String> releaseKillSwitch(@Nullable String tenantId, @Nullable String agentType, String by,
                                          String reason) {
        List<String> released = new ArrayList<>();
        for (AgentRegistration agent : scope(tenantId, agentType)) {
            if (agent.status() != AgentStatus.SUSPENDED || agent.statusReason() == null
                    || !agent.statusReason().startsWith(KILL_SWITCH_REASON)) {
                continue;
            }
            registry.resume(agent.tenantId(), agent.agentId(), "RELEASED: " + Objects.toString(reason, ""))
                    .ifPresent(resumed -> released.add(resumed.agentId()));
        }
        record(AuditEventCategory.AGENT_KILL_SWITCH, by, Objects.toString(agentType, "*"), "KILL_SWITCH_OFF", reason,
                null, null, null, tenantId, Map.of("agents", String.join(", ", released)));
        return released;
    }

    private List<AgentRegistration> scope(@Nullable String tenantId, @Nullable String agentType) {
        if (registry == null) {
            throw new IllegalStateException("The kill switch needs the agent registry");
        }
        return registry.list(tenantId, KILL_SWITCH_SCOPE).stream()
                .filter(agent -> !StringUtils.hasText(agentType) || agentType.trim().equals(agent.agentType()))
                .toList();
    }

    private Optional<String> revokeDelegation(@Nullable String delegationId, String reason) {
        if (delegations == null || !StringUtils.hasText(delegationId)) {
            return Optional.empty();
        }
        try {
            return delegations.revoke(delegationId, REVOKED_BY, reason).map(revoked -> "DELEGATION_REVOKED");
        } catch (RuntimeException e) {
            log.error("Delegation revocation failed after a BLOCK: delegationId={}", delegationId, e);
            return Optional.of("DELEGATION_REVOCATION_FAILED");
        }
    }

    private Optional<String> revokeTokens(String principal, String clientId) {
        if (revoker == null) {
            return Optional.empty();
        }
        try {
            int revoked = revoker.revoke(principal, clientId);
            return Optional.of(revoked < 0 ? "TOKENS_NOT_REVOCABLE" : "TOKENS_REVOKED(" + revoked + ")");
        } catch (RuntimeException e) {
            log.error("Token revocation failed after a BLOCK: clientId={}", clientId, e);
            return Optional.of("TOKEN_REVOCATION_FAILED");
        }
    }

    private Optional<String> suspend(@Nullable String tenantId, String agentId, String reason) {
        if (registry == null) {
            return Optional.empty();
        }
        try {
            return registry.suspend(tenantId, agentId, reason).map(suspended -> "AGENT_SUSPENDED");
        } catch (UnsupportedOperationException e) {
            return Optional.of("AGENT_SUSPENSION_UNSUPPORTED");
        } catch (RuntimeException e) {
            log.error("Agent suspension failed after a BLOCK: agentId={}", agentId, e);
            return Optional.of("AGENT_SUSPENSION_FAILED");
        }
    }

    private Optional<String> notifyStop(@Nullable String tenantId, @Nullable String recipient, String agentId,
                                        @Nullable String delegationId, String subject, String message,
                                        @Nullable String correlationId, String step) {
        if (notices == null) {
            return Optional.empty();
        }
        try {
            AgentNotice notice = notices.notify(AgentNotice.AGENT_STOPPED, tenantId, recipient, agentId, delegationId,
                    subject, message, null, correlationId);
            return notice != null ? Optional.of(step + "(" + notice.deliveredBy() + ")") : Optional.empty();
        } catch (RuntimeException e) {
            log.error("Agent stop notice failed: agentId={}", agentId, e);
            return Optional.of(step + "_FAILED");
        }
    }

    /** The agent's registration, for its client and its sponsor; empty when unknown. */
    private Optional<AgentRegistration> registration(@Nullable String tenantId, String agentId) {
        if (registry == null) {
            return Optional.empty();
        }
        try {
            return AgentRegistrations.find(registry, tenantId, agentId);
        } catch (RuntimeException e) {
            log.error("Agent registry lookup failed: agentId={}", agentId, e);
            return Optional.empty();
        }
    }

    /** The person accountable for the request (A1-6): the delegator, else the sponsor. */
    @Nullable
    private static String accountable(Map<String, Object> metadata, @Nullable String delegator) {
        Object accountable = metadata.get("agentAccountableId");
        if (accountable != null && StringUtils.hasText(accountable.toString())) {
            return accountable.toString().trim();
        }
        Object sponsor = metadata.get("agentSponsorId");
        return StringUtils.hasText(delegator) ? delegator
                : sponsor != null && StringUtils.hasText(sponsor.toString()) ? sponsor.toString().trim() : null;
    }

    @Nullable
    private static String correlation(Map<String, Object> metadata) {
        Object requestId = metadata.get("requestId");
        return requestId != null ? requestId.toString() : null;
    }

    private void record(AuditEventCategory category, String principal, String agentId, String action,
                        @Nullable String reason, @Nullable String subjectKind, @Nullable String delegatorId,
                        @Nullable String delegationId, @Nullable String tenantId, Map<String, String> details) {
        if (audit == null) {
            return;
        }
        audit.recordSync(AuditRecord.builder()
                .eventCategory(category)
                .principalName(principal)
                .resourceIdentifier(agentId)
                .eventSource("CORE")
                .action(action)
                .decision(action)
                .outcome(action)
                .reason(reason)
                .subjectKind(subjectKind)
                .agentId(agentId)
                .delegatorId(delegatorId)
                .delegationId(delegationId)
                .tenantId(tenantId)
                .correlationId(StringUtils.hasText(details.get("correlationId")) ? details.get("correlationId") : null)
                .details(new LinkedHashMap<String, Object>(details))
                .build());
    }

    private static void requireText(String value, String name) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
