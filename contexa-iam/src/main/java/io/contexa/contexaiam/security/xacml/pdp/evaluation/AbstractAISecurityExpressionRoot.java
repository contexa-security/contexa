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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.security.bridge.AgentRequestConfirmation;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;

@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;
    protected final ZeroTrustActionRepository actionRedisRepository;

    protected AbstractAISecurityExpressionRoot(Authentication authentication,
                                               AuthorizationContext authorizationContext,
                                               AuditLogRepository auditLogRepository,
                                               ZeroTrustActionRepository actionRedisRepository) {
        super(authentication);
        this.authorizationContext = authorizationContext;
        this.auditLogRepository = auditLogRepository;
        this.actionRedisRepository = actionRedisRepository;
    }

    protected String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return authentication.getName();
    }

    protected ZeroTrustAction getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
        // docs/agent A5-1: an agent acting for the user is judged by its own decision.
        ZeroTrustSubject subject = decisionSubject(userId);
        ZeroTrustAction action = subject != null ? subject.currentAction(actionRedisRepository)
                : actionRedisRepository.getCurrentAction(userId);
        // docs/agent A5-2: the accountable person confirmed this very request of the agent; it answers the CHALLENGE.
        return action == ZeroTrustAction.CHALLENGE && agentRequestConfirmed() ? ZeroTrustAction.ALLOW : action;
    }

    /**
     * docs/agent A5-2 (A1-9): whether the person accountable for the agent confirmed this very request, so that a
     * policy can let an agent's request through only once confirmed ({@code !delegationRequiresApproval() or
     * agentRequestConfirmed()}).
     */
    public boolean agentRequestConfirmed() {
        return isAgent() && AgentRequestConfirmation.of(currentRequest()) != null;
    }

    /** docs/agent A5-1: whose decision this evaluation reads; null without a user. */
    protected ZeroTrustSubject decisionSubject(String userId) {
        return ZeroTrustSubject.of(userId, delegationStamp());
    }

    public boolean isAllowed() {
        return getCurrentAction() == ZeroTrustAction.ALLOW;
    }

    public boolean isBlocked() {
        return getCurrentAction() == ZeroTrustAction.BLOCK;
    }

    public boolean needsChallenge() {
        return getCurrentAction() == ZeroTrustAction.CHALLENGE;
    }

    public boolean needsEscalation() {
        return getCurrentAction() == ZeroTrustAction.ESCALATE;
    }

    public boolean isPendingAnalysis() {
        return getCurrentAction() == ZeroTrustAction.PENDING_ANALYSIS;
    }

    public boolean hasAction(String expectedAction) {
        return ZeroTrustAction.fromString(expectedAction) == getCurrentAction();
    }

    public boolean hasActionIn(String... allowedActions) {
        ZeroTrustAction action = getCurrentAction();
        return Arrays.stream(allowedActions)
                .anyMatch(a -> ZeroTrustAction.fromString(a) == action);
    }

    // A1-9 (AG-11d): the agent facts of the request, as the bridge stated them, for deterministic policies. Each
    // reads the request's delegation stamp; a person's request has none, so every agent condition is false for it.

    /** Whether an agent makes the request, acting for a person or on its own. */
    public boolean isAgent() {
        DelegationStamp stamp = delegationStamp();
        return stamp != null && hasText(stamp.agentId());
    }

    /** Whether an agent acting for a person makes the request. */
    public boolean isDelegatedAgent() {
        return isAgent() && delegationStamp().delegated();
    }

    /** Whether an agent acting on its own makes the request. */
    public boolean isAutonomousAgent() {
        return isAgent() && !delegationStamp().delegated();
    }

    /** The agent making the request, or {@code null} for a person's request. */
    public String getAgentId() {
        return isAgent() ? delegationStamp().agentId().trim() : null;
    }

    /** Whether the request's agent is one of these. */
    public boolean isAgentIn(String... agentIds) {
        String agentId = getAgentId();
        return agentId != null && agentIds != null && Arrays.asList(agentIds).contains(agentId);
    }

    /** The person a delegated agent acts for, or {@code null}. */
    public String getDelegatorId() {
        return isDelegatedAgent() && hasText(delegationStamp().subjectId()) ? delegationStamp().subjectId().trim() : null;
    }

    /** How many delegations lead to the request's agent: 0 for a person or an agent on its own, 1 for a direct one. */
    public int getDelegationChainDepth() {
        if (!isAgent()) {
            return 0;
        }
        DelegationStamp stamp = delegationStamp();
        if (stamp.attributes().get("delegationChainDepth") instanceof Number depth) {
            return depth.intValue();
        }
        return stamp.delegated() ? 1 : 0;
    }

    /** Whether the delegation chain is no deeper than the maximum. */
    public boolean delegationChainDepthAtMost(int maximum) {
        return getDelegationChainDepth() <= maximum;
    }

    /** Whether the delegation lists the operation among the operations it delegates. */
    public boolean delegationAllowsOperation(String operation) {
        return isAgent() && operation != null && delegationStamp().allowedOperations().stream()
                .anyMatch(allowed -> allowed.equalsIgnoreCase(operation.trim()));
    }

    /**
     * Whether the delegation lists the resource among the resources it delegates; a listed resource ending in
     * {@code *} covers every resource starting with what precedes it.
     */
    public boolean delegationAllowsResource(String resource) {
        if (!isAgent() || resource == null) {
            return false;
        }
        String wanted = resource.trim();
        return delegationStamp().allowedResources().stream().anyMatch(allowed -> allowed.endsWith("*")
                ? wanted.startsWith(allowed.substring(0, allowed.length() - 1))
                : allowed.equals(wanted));
    }

    /** Whether the delegation states that a person must approve the agent's work. */
    public boolean delegationRequiresApproval() {
        return isDelegatedAgent() && Boolean.TRUE.equals(delegationStamp().approvalRequired());
    }

    /**
     * docs/agent A5-7 (A1-9): whether the agent's delegation made at most {@code max} requests in the last minute,
     * this one included, as the call limits counted them; true for a person, and when nothing counted them.
     */
    public boolean agentCallsInLastMinuteAtMost(int max) {
        if (!isAgent()) {
            return true;
        }
        HttpServletRequest request = currentRequest();
        Object calls = request != null ? request.getAttribute(BridgeRequestAttributes.AGENT_RECENT_CALLS) : null;
        return !(calls instanceof Integer count) || count <= max;
    }

    /** The request's delegation stamp, from the request this evaluation is for. */
    protected DelegationStamp delegationStamp() {
        HttpServletRequest request = currentRequest();
        return request != null && request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                ? stamp
                : null;
    }

    /** The request this evaluation is for, or null. */
    private HttpServletRequest currentRequest() {
        HttpServletRequest request = authorizationContext != null && authorizationContext.environment() != null
                ? authorizationContext.environment().request()
                : null;
        if (request == null && RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            request = attributes.getRequest();
        }
        return request;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public boolean hasActionOrDefault(String defaultAction, String... allowedActions) {
        ZeroTrustAction action = getCurrentAction();
        if (action == ZeroTrustAction.PENDING_ANALYSIS) {
            action = ZeroTrustAction.fromString(defaultAction);
        }

        final ZeroTrustAction finalAction = action;
        return Arrays.stream(allowedActions)
                .anyMatch(a -> ZeroTrustAction.fromString(a) == finalAction);
    }
}