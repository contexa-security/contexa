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
package io.contexa.contexaiam.admin.web.dashboard;

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Alert;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Component;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.CoverageCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DayPoint;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Header;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ImpactCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Period;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.StoppedCard;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.TrustCard;

import java.util.List;
import java.util.Map;

/**
 * The admin dashboard's answer (plan step 9, approved mockup v4): one JSON document the dashboard's script draws, a
 * part for each card. A number of the period is the period's; a number of "now" is the state at the time of the call.
 * The Zero Trust part is the console's own overview, so the dashboard and the console say the same.
 */
public final class DashboardDtos {

    private DashboardDtos() {
    }

    /** The dashboard of a period: its parts in the order of the screen. */
    public record DashboardView(Period period, ZeroTrustPart zeroTrust, OperationsPart operations, PolicyPart policy,
                                IamPart iam, SecurityPart security, BlockedPart blocked, AgentsPart agents,
                                SystemPart system, AttentionPart attention, ChangesPart changes, DenialsPart denials) {
    }

    /** A count of a key (a status, a kind, a resource, a user). */
    public record Count(String key, long count) {
    }

    /** A count of a day (yyyy-MM-dd, the server's zone). */
    public record DayCount(String day, long count) {
    }

    /**
     * The Zero Trust console's overview of the period (its band, its numbers, its daily trend and its warnings), the
     * decisions waiting for review and, in SHADOW, the adoption's verdict.
     */
    public record ZeroTrustPart(Header header, OverviewSummary summary, CoverageCard coverage, StoppedCard stopped,
                                ImpactCard impact, TrustCard trust, List<DayPoint> trend, List<Alert> alerts,
                                long reviewPending, AdoptionState adoption) {
    }

    /** The adoption screen's verdict and the number of its criteria not met yet. */
    public record AdoptionState(String verdict, int unmet) {
    }

    /** N12: the parts of the decision path and their state, as the operations screen shows them. */
    public record OperationsPart(List<Component> components) {
    }

    /**
     * The resources by protection, the policies by approval, the policy check's findings (null counts when the check
     * could not run), the policy changes of the last seven days and the permissions nothing uses (N5, N14).
     */
    public record PolicyPart(long resourceTotal, long resourcePolicyConnected, long resourcePermissionCreated,
                             long resourceNeedsDefinition, long policyCount, long activePolicies, long pendingApproval,
                             long approved, long rejected, String healthStatus, Integer conflictCount,
                             Integer duplicateCount, List<DayCount> changesByDay, long unusedPermissions) {
    }

    /**
     * The accounts now. userCount, groupCount, roleCount and permissionCount are the access center's counts;
     * activeAccounts and mfaEnabled are counted among the enabled accounts of people (N4); admins and adminsWithoutMfa
     * by the console's administrator rule (N2); locked, dormant and expired among the enabled accounts of people (N3).
     */
    public record IamPart(long userCount, long groupCount, long roleCount, long permissionCount, long activeAccounts,
                          long mfaEnabled, long admins, long adminsWithoutMfa, long usersWithoutFactor, long locked,
                          long dormant, long expired, boolean activeHierarchies) {
    }

    /**
     * The failed authentications of the period and of each of the last seven days (N15), the administrator overrides
     * and the broken decision record seals of the period (N7), the deny rules in force (N9) and the sessions of the
     * last 30 minutes (N8).
     */
    public record SecurityPart(long authFailure, List<DayCount> failuresByDay, long overrides, long sealMismatch,
                               long ipDeny, long recentSessions) {
    }

    /** N6: the users blocked now, by the state of the latest record of each. */
    public record BlockedPart(long inForce, List<Count> byLatestStatus) {
    }

    /**
     * N10, N16: the agents by status, the delegations and confirmations now, the alarms of the period and the agents
     * narrowed or stopped now, and when each kind last happened.
     */
    public record AgentsPart(List<Count> byStatus, long delegations, long confirmations, long confirmationsOverdue,
                             long callLimit, long denialAlarm, long narrowed, long stoppedDelegations,
                             Map<String, String> lastAt) {
    }

    /** The settings in effect and the latest mode change (N13). */
    public record SystemPart(String mode, String modeSince, LastChange lastModeChange, String combining,
                             String missingMethodDecision, String noMatchingUrlDecision, int auditRetentionDays,
                             boolean standalone) {
    }

    /** When and by whom. */
    public record LastChange(String at, String by) {
    }

    /**
     * N17: the users to look at, the most problem signals first, and how many users have a signal at all; capped when
     * a source had more users than were read, and the count is then a lower bound.
     */
    public record AttentionPart(long withSignals, boolean capped, List<AttentionRow> rows) {
    }

    /** A user and the signals gathered for them; the request of the block in force, when there is one. */
    public record AttentionRow(String user, List<Signal> signals, String lastAt, String requestId) {
    }

    /** A signal and its count, for the kinds that have one. */
    public record Signal(String kind, Long count) {
    }

    /**
     * N19: the period's admin changes by kind and the latest of them; the action is null when no words name it, and the
     * kind names it then.
     */
    public record ChangesPart(List<Count> byKind, List<ChangeRow> recent) {
    }

    public record ChangeRow(String at, String actor, String kind, String action, String target) {
    }

    /** N20: the period's refused requests of signed-in users, and the resources and users refused most. */
    public record DenialsPart(long total, List<Count> resources, List<Count> users) {
    }
}
