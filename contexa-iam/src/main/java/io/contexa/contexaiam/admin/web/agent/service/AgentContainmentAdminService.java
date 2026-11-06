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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacore.autonomous.agent.AgentNotice;
import io.contexa.contexacore.autonomous.agent.AgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.AgentRegistration;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentScopeRestriction;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The console's agent stops (docs/agent A5-3, AM-4): the agents suspended, the agents stopped while they acted for a
 * person, why (the decision a stop names), the release of either, the kill switch and the history. Every action is
 * done by the core containment and leaves an audit record.
 */
public class AgentContainmentAdminService {

    static final int LIST_LIMIT = 500;
    private static final ObjectMapper JSON = new ObjectMapper();
    static final List<String> STOP_CATEGORIES = List.of("AGENT_STOPPED", "AGENT_RELEASED", "AGENT_KILL_SWITCH");
    private static final String ALL_AGENTS = "*";

    private final AgentContainmentService containment;
    private final AgentRegistry registry;
    private final AuditLogRepository auditLog;
    private final AgentNoticeStore notices;

    public AgentContainmentAdminService(@Nullable AgentContainmentService containment, AgentRegistry registry,
                                        @Nullable AuditLogRepository auditLog, @Nullable AgentNoticeStore notices) {
        this.containment = containment;
        this.registry = registry;
        this.auditLog = auditLog;
        this.notices = notices;
    }

    private AgentScopeService scopes;

    /** docs/agent A5-4: the narrowed scopes, shown with the stops. */
    public void setScopes(@Nullable AgentScopeService scopes) {
        this.scopes = scopes;
    }

    private BlockedUserService blockedUsers;

    /** Tells a session under a restriction of its own, which reads the stops and acts on none of them. */
    public void setBlockedUsers(@Nullable BlockedUserService blockedUsers) {
        this.blockedUsers = blockedUsers;
    }

    /**
     * Whether the acting administrator stands under a restriction of their own this session has not answered (a BLOCK,
     * a CHALLENGE or an ESCALATE), as the block list judges it ({@link BlockedUserService#underOwnBlock}).
     */
    public boolean underOwnBlock(String adminId) {
        return blockedUsers != null && blockedUsers.underOwnBlock(adminId);
    }

    /** docs/agent A5-4: the agents whose scope a decision narrowed and that are still narrowed. */
    public List<AgentScopeRestriction> narrowedAgents() {
        return scopes != null ? scopes.inForce() : List.of();
    }

    /** Whether the stops can be acted on: the autonomous security plane runs. */
    public boolean available() {
        return containment != null;
    }

    /** An agent stopped while it acted for a person, with the record of the stop and the decision it names. */
    public record StoppedDelegation(String userId, String agentId, @Nullable String delegationId,
                                    LocalDateTime stoppedAt, @Nullable String reason, @Nullable String steps,
                                    @Nullable Long decisionRecordId) {
    }

    /** The agents suspended, latest seen first. */
    public List<AgentRegistration> suspendedAgents() {
        return registry.list(null, LIST_LIMIT).stream()
                .filter(agent -> agent.status() == AgentStatus.SUSPENDED)
                .toList();
    }

    /** The agents stopped while they acted for a person and not released since, latest first. */
    public List<StoppedDelegation> stoppedDelegations() {
        if (auditLog == null) {
            return List.of();
        }
        Map<String, AuditLog> latest = new LinkedHashMap<>();
        Map<String, LocalDateTime> released = new HashMap<>();
        for (AuditLog row : auditLog.findTop500ByEventCategoryInOrderByTimestampDesc(STOP_CATEGORIES)) {
            if (!"DELEGATED_AGENT".equals(row.getSubjectKind()) || !StringUtils.hasText(row.getDelegatorId())) {
                continue;
            }
            String key = row.getDelegatorId() + "::" + row.getAgentId();
            if ("AGENT_RELEASED".equals(row.getEventCategory())) {
                released.putIfAbsent(key, row.getTimestamp());
            } else if ("AGENT_STOPPED".equals(row.getEventCategory())) {
                latest.putIfAbsent(key, row);
            }
        }
        List<StoppedDelegation> stopped = new ArrayList<>();
        latest.forEach((key, row) -> {
            LocalDateTime release = released.get(key);
            if (release != null && !release.isBefore(row.getTimestamp())) {
                return;
            }
            stopped.add(new StoppedDelegation(row.getDelegatorId(), row.getAgentId(), row.getDelegationId(),
                    row.getTimestamp(), row.getReason(), stepsOf(row), decisionRecordId(row.getCorrelationId())));
        });
        return stopped;
    }

    /** The stops, releases and kill switch uses, latest first. */
    public List<AuditLog> history() {
        return auditLog != null ? auditLog.findTop500ByEventCategoryInOrderByTimestampDesc(STOP_CATEGORIES).stream()
                .limit(100).toList() : List.of();
    }

    /** The latest notices to the people accountable for agents. */
    public List<AgentNotice> notices() {
        return notices != null ? notices.list(null, 50) : List.of();
    }

    public void releaseDelegatedAgent(String userId, String agentId, String adminId, String reason) {
        refuseUnderOwnBlock(adminId, "RELEASE_DELEGATION", agentId);
        requireAvailable().releaseDelegatedAgent(userId, agentId, adminId, reason);
    }

    public boolean releaseAgent(@Nullable String tenantId, String agentId, String adminId, String reason) {
        refuseUnderOwnBlock(adminId, "RELEASE_AGENT", agentId);
        return requireAvailable().releaseAgent(tenantId, agentId, adminId, reason);
    }

    public List<String> killSwitch(@Nullable String tenantId, @Nullable String agentType, String adminId,
                                   String reason) {
        refuseUnderOwnBlock(adminId, "KILL_SWITCH", StringUtils.hasText(agentType) ? agentType : ALL_AGENTS);
        return requireAvailable().killSwitch(blankToNull(tenantId), blankToNull(agentType), adminId, reason);
    }

    public List<String> releaseKillSwitch(@Nullable String tenantId, @Nullable String agentType, String adminId,
                                          String reason) {
        refuseUnderOwnBlock(adminId, "KILL_SWITCH_RELEASE", StringUtils.hasText(agentType) ? agentType : ALL_AGENTS);
        return requireAvailable().releaseKillSwitch(blankToNull(tenantId), blankToNull(agentType), adminId, reason);
    }

    private void refuseUnderOwnBlock(String adminId, String action, String target) {
        if (blockedUsers != null) {
            blockedUsers.refuseUnderOwnBlock(adminId, action, target);
        }
    }

    private AgentContainmentService requireAvailable() {
        if (containment == null) {
            throw new IllegalStateException("Agent stops need the autonomous security plane");
        }
        return containment;
    }

    @Nullable
    private Long decisionRecordId(@Nullable String correlationId) {
        if (auditLog == null || !StringUtils.hasText(correlationId)) {
            return null;
        }
        Optional<AuditLog> decision = auditLog.findTopByCorrelationIdAndEventCategoryOrderByIdDesc(correlationId,
                "SECURITY_DECISION");
        return decision.map(AuditLog::getId).orElse(null);
    }

    @Nullable
    private static String stepsOf(AuditLog row) {
        if (!StringUtils.hasText(row.getDetails())) {
            return null;
        }
        try {
            Object steps = JSON.readValue(row.getDetails(), Map.class).get("steps");
            return steps != null && StringUtils.hasText(steps.toString()) ? steps.toString() : null;
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    @Nullable
    private static String blankToNull(@Nullable String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
