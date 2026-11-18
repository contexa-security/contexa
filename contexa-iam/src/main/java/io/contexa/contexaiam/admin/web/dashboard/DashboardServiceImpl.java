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

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacore.autonomous.agent.AgentScopeRestriction;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService.StoppedDelegation;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessCenterStats;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AdoptionState;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AgentsPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AttentionPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AttentionRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.BlockedPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ChangeRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ChangesPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Count;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DashboardView;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DenialsPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.IamPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.LastChange;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.OperationsPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.PolicyPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.SecurityPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Signal;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.SystemPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ZeroTrustPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.AccountSignal;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.Accounts;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.Alarm;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.BlockRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.ChangeRecord;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Adoption;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ModeChange;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Overview;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Period;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.UserChallenges;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.service.DefaultPolicyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The admin dashboard (plan step 9, approved mockup v4): each card's numbers read from the service of its screen, the
 * Zero Trust card's from the console's overview, the rest from {@link DashboardQueries} and the dashboard's hourly
 * tables ({@link DashboardHourlyStats}). Nothing is loaded to be counted: every number is one statement's count.
 * The work to do and the area states are worked out by the screen from these numbers, by the rules its tooltips name.
 */
@Slf4j
public class DashboardServiceImpl implements DashboardService {

    /** The periods of the dashboard's chips, the default 7 days; a period of chosen days is the console's alone. */
    static final List<String> PERIODS = List.of("day", "week", "month", "quarter");
    /** How many users the card of users to look at shows. */
    static final int ATTENTION_SHOWN = 8;
    /** How many users each signal's source is read for: the count of users with a signal is a lower bound past it. */
    static final int ATTENTION_READ = 500;
    /** The step-ups in the period from which a user is one to look at (the approved rule: three). */
    static final int CHALLENGES_AT_LEAST = 3;
    /** How many admin changes the timeline shows. */
    static final int CHANGES_SHOWN = 8;
    /** K109: the words of the actor of a version registered from a node's document folder. */
    static final String FOLDER_ACTOR_WORDS = "dashboard.ui.changes.folderActor";
    /** How many resources and users the refusals rank. */
    static final int DENIALS_RANKED = 5;
    /** The days of the daily bars and of the heat strip, today included. */
    static final int DAYS_SHOWN = 7;
    /** The days without a sign-in that make an account dormant. */
    static final int DORMANT_DAYS = 90;
    /** The time a session counts as in use after its last request. */
    static final Duration RECENT_SESSION = Duration.ofMinutes(30);

    static final String AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE";
    static final List<String> POLICY_CHANGES = List.of("POLICY_CREATED", "POLICY_UPDATED", "POLICY_DELETED");
    static final String CALL_LIMIT = "AGENT_CALL_LIMIT_EXCEEDED";
    static final String DENIAL_ALARM = "AGENT_DENIAL_RATE_ALARM";

    /** The block states that are a problem of their own; a release request and the rest are a warning. */
    static final Set<String> PROBLEM_SIGNALS = Set.of("BLOCKED", "MFA_FAILED", "TIMEOUT_RESPONDED", "ADMIN_NO_MFA",
            "REPEATED");
    /** The order of a user's signals in a row: the block first, then the account's, then the period's. */
    static final List<String> SIGNAL_ORDER = List.of("BLOCKED", "UNBLOCK_REQUESTED", "MFA_FAILED", "TIMEOUT_RESPONDED",
            "REPEATED", "ADMIN_NO_MFA", "LOCKED", "LOGIN_FAILURES", "CHALLENGES");

    /** The actions the timeline has words for; any other is named by its kind. */
    static final Set<String> NAMED_ACTIONS = namedActions();

    private final DashboardSources sources;
    private final Clock clock;

    public DashboardServiceImpl(DashboardSources sources, @Nullable Clock clock) {
        this.sources = Objects.requireNonNull(sources, "sources");
        this.clock = clock != null ? clock : Clock.systemDefaultZone();
    }

    private static Set<String> namedActions() {
        List<String> actions = new ArrayList<>(List.of("POLICY_CREATED", "POLICY_UPDATED", "POLICY_DELETED",
                "POLICY_APPROVED", "POLICY_REJECTED", "ROLE_CREATED", "ROLE_UPDATED", "ROLE_DELETED", "USER_CREATED",
                "USER_MODIFIED", "USER_UNLOCKED", "USER_DELETED", "ZERO_TRUST_MODE_CHANGED", "APPROVE", "DENY",
                "RELEASE_CHALLENGE", "AGENT_REGISTERED", "AGENT_DEREGISTERED", "AGENT_REMOVED", "AGENT_SPONSOR_CHANGED",
                "AGENT_SECRET_ROTATED", "AGENT_RELEASED", "KILL_SWITCH_ON", "KILL_SWITCH_OFF"));
        actions.addAll(List.of(PromptVersionAudit.CREATED, PromptVersionAudit.HIDDEN, PromptVersionAudit.IMPORTED,
                PromptVersionAudit.FOLDER_REGISTERED, PromptVersionAudit.USED_FOR_DECISIONS,
                PromptVersionAudit.CANARY_STARTED, PromptVersionAudit.CANARY_STOPPED, PromptVersionAudit.SHADOW_STARTED,
                PromptVersionAudit.SHADOW_STOPPED, PromptVersionAudit.EMERGENCY_ROLLBACK,
                PromptVersionAudit.ROLLBACK_APPROVED, PromptVersionAudit.TRIAL_STARTED,
                PromptVersionAudit.TRIAL_CANCELLED));
        return Set.copyOf(actions);
    }

    @Override
    public DashboardView dashboard(String period, Locale locale) {
        String key = period == null || period.isBlank() ? "week" : period.trim().toLowerCase(Locale.ROOT);
        if (!PERIODS.contains(key)) {
            throw new IllegalArgumentException("The dashboard's period is one of " + PERIODS);
        }
        Period range = sources.console().period(key);
        Instant from = Instant.parse(range.from());
        Instant to = Instant.parse(range.to());
        Instant now = clock.instant();
        ZeroTrustPart zeroTrust = zeroTrust(range.key(), locale);
        return new DashboardView(range, zeroTrust,
                new OperationsPart(sources.console().components(range.key(), locale)),
                policy(now), iam(now), security(from, to, now), blocked(), agents(from, to, now),
                system(zeroTrust), attention(range.key(), now), changes(from, to, locale), denials(from, to));
    }

    // ----- Zero Trust (the console's overview, N12, N13) -----

    private ZeroTrustPart zeroTrust(String period, Locale locale) {
        Overview overview = sources.console().overview(period, null, null, null, locale);
        AdoptionState adoption = null;
        if ("SHADOW".equals(overview.header().mode())) {
            // Only SHADOW weighs the adoption; reading it otherwise would cost its 90 days for nothing.
            Adoption state = sources.console().adoption(null, locale);
            adoption = new AdoptionState(state.verdict(), state.unmet());
        }
        return new ZeroTrustPart(overview.header(), overview.summary(), overview.coverage(), overview.stopped(),
                overview.impact(), overview.trust(), overview.trend(), overview.alerts(),
                sources.decisionRecords().reviewPending(), adoption);
    }

    private SystemPart system(ZeroTrustPart zeroTrust) {
        SystemSettings settings = sources.systemSettings().getSettings();
        ModeChange change = sources.console().lastModeChange();
        return new SystemPart(zeroTrust.header().mode(), zeroTrust.header().modeSince(),
                change != null ? new LastChange(change.at(), change.by()) : null,
                sources.combining().getCombiningAlgorithm().name(),
                sources.combining().getMissingMethodPolicyDecision().name(),
                sources.combining().getNoMatchingUrlPolicyDecision().name(), settings.getAuditLogRetentionDays(),
                zeroTrust.header().standalone());
    }

    // ----- policy (N5, N14) -----

    private PolicyPart policy(Instant now) {
        Map<ManagedResource.Status, Long> resources = new EnumMap<>(ManagedResource.Status.class);
        long resourceTotal = 0;
        for (Object[] row : sources.resources().countGroupByStatus()) {
            if (row.length >= 2 && row[0] instanceof ManagedResource.Status status && row[1] instanceof Number count) {
                resources.merge(status, count.longValue(), Long::sum);
                resourceTotal += count.longValue();
            }
        }
        Map<Policy.ApprovalStatus, Long> approvals = new EnumMap<>(Policy.ApprovalStatus.class);
        for (Object[] row : sources.policies().countGroupByApprovalStatus()) {
            if (row.length >= 2 && row[1] instanceof Number count) {
                // A policy without an approval state waits for one, as the policy center lists it.
                Policy.ApprovalStatus status = row[0] instanceof Policy.ApprovalStatus value ? value
                        : Policy.ApprovalStatus.PENDING;
                approvals.merge(status, count.longValue(), Long::sum);
            }
        }
        String health;
        Integer conflicts;
        Integer duplicates;
        try {
            // D65: kept between loads until the policies change, instead of comparing all of them on every load.
            FullValidationReport report = sources.policyValidation().validateAllForDashboard();
            health = report.healthStatus();
            conflicts = report.conflicts().size();
            duplicates = report.duplicates().size();
        } catch (RuntimeException e) {
            // A check that could not run says so: its counts are unknown, not zero.
            log.error("[Dashboard] The policy check could not run", e);
            health = "UNKNOWN";
            conflicts = null;
            duplicates = null;
        }
        LocalDate firstDay = firstDay(now);
        return new PolicyPart(resourceTotal, resources.getOrDefault(ManagedResource.Status.POLICY_CONNECTED, 0L),
                resources.getOrDefault(ManagedResource.Status.PERMISSION_CREATED, 0L),
                resources.getOrDefault(ManagedResource.Status.NEEDS_DEFINITION, 0L), sources.policies().count(),
                sources.policies().countByIsActiveTrue(), approvals.getOrDefault(Policy.ApprovalStatus.PENDING, 0L),
                approvals.getOrDefault(Policy.ApprovalStatus.APPROVED, 0L),
                approvals.getOrDefault(Policy.ApprovalStatus.REJECTED, 0L), health, conflicts, duplicates,
                sources.queries().changesByDay(POLICY_CHANGES, firstDay, start(firstDay), now),
                sources.policyCenter().countUnusedPermissions());
    }

    // ----- IAM (N2, N3, N4) -----

    private IamPart iam(Instant now) {
        AccessCenterStats stats = sources.accessCenter().getStats();
        int expiryDays = sources.passwordPolicy().getCurrentPolicy().getPasswordExpiryDays();
        Accounts accounts = sources.queries().accounts(now, now.minus(Duration.ofDays(DORMANT_DAYS)),
                expiryDays > 0 ? now.minus(Duration.ofDays(expiryDays)) : null);
        return new IamPart(stats.userCount(), stats.groupCount(), stats.roleCount(), stats.permissionCount(),
                accounts.active(), accounts.mfaEnabled(), sources.administrators().administratorCount(),
                sources.administrators().administratorsWithoutMfaCount(),
                sources.verificationCoverage().usersWithoutFactor(), accounts.locked(), accounts.dormant(),
                accounts.expired(), sources.roleHierarchies().existsByIsActiveTrue());
    }

    // ----- security (N7, N8, N9, N15) -----

    private SecurityPart security(Instant from, Instant to, Instant now) {
        LocalDate firstDay = firstDay(now);
        return new SecurityPart(sources.queries().count(AUTHENTICATION_FAILURE, from, to),
                sources.queries().byDay(List.of(AUTHENTICATION_FAILURE), firstDay, start(firstDay), now),
                sources.auditLog().countAdminOverridesBetween(local(from), local(to)),
                sources.queries().sealMismatches(from, to),
                sources.ipRules().countDenyRules(), sources.queries().sessionsSince(now.minus(RECENT_SESSION)));
    }

    // ----- blocks (N6) -----

    private BlockedPart blocked() {
        Map<String, Long> byStatus = sources.queries().blocksByLatestStatus();
        List<Count> counts = new ArrayList<>();
        long inForce = 0;
        for (String status : List.of("BLOCKED", "UNBLOCK_REQUESTED", "MFA_FAILED", "TIMEOUT_RESPONDED")) {
            long count = byStatus.getOrDefault(status, 0L);
            inForce += count;
            if (count > 0) {
                counts.add(new Count(status, count));
            }
        }
        return new BlockedPart(inForce, counts);
    }

    // ----- agents (N10, N16) -----

    private AgentsPart agents(Instant from, Instant to, Instant now) {
        List<Count> byStatus = new ArrayList<>();
        if (sources.agents() != null) {
            Map<AgentStatus, Long> counts = sources.agents().countByStatus(null);
            for (AgentStatus status : AgentStatus.values()) {
                long count = counts.getOrDefault(status, 0L);
                if (count > 0) {
                    byStatus.add(new Count(status.name(), count));
                }
            }
        }
        long delegations = sources.delegations() != null ? sources.delegations().countValidAt(now) : 0;
        long waiting = sources.confirmations() != null ? sources.confirmations().countWaiting(now) : 0;
        long overdue = sources.confirmations() != null ? sources.confirmations().countOverdue(now) : 0;
        Map<String, Alarm> alarms = sources.queries().alarms(List.of(CALL_LIMIT, DENIAL_ALARM), from, to);
        List<AgentScopeRestriction> narrowed = sources.containment() != null ? sources.containment().narrowedAgents()
                : List.of();
        List<StoppedDelegation> stopped = sources.containment() != null ? sources.containment().stoppedDelegations()
                : List.of();
        Map<String, String> lastAt = new LinkedHashMap<>();
        putTime(lastAt, "callLimit", alarms.get(CALL_LIMIT).lastAt());
        putTime(lastAt, "denialAlarm", alarms.get(DENIAL_ALARM).lastAt());
        putTime(lastAt, "narrowed", narrowed.stream().map(AgentScopeRestriction::narrowedAt).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null));
        putTime(lastAt, "stoppedDelegations", stopped.stream().map(StoppedDelegation::stoppedAt)
                .filter(Objects::nonNull).max(Comparator.naturalOrder())
                .map(at -> at.atZone(ZoneId.systemDefault()).toInstant()).orElse(null));
        return new AgentsPart(byStatus, delegations, waiting, overdue, alarms.get(CALL_LIMIT).count(),
                alarms.get(DENIAL_ALARM).count(), narrowed.size(), stopped.size(), lastAt);
    }

    private static void putTime(Map<String, String> times, String key, @Nullable Instant at) {
        if (at != null) {
            times.put(key, at.toString());
        }
    }

    // ----- the users to look at (N17, N18) -----

    /** A user's signals while they are gathered. */
    private static final class Gathered {
        private final String user;
        private final Map<String, Long> signals = new LinkedHashMap<>();
        private Instant lastAt;
        private String requestId;

        private Gathered(String user) {
            this.user = user;
        }

        private void signal(String kind, @Nullable Long count, @Nullable Instant at) {
            signals.put(kind, count);
            if (at != null && (lastAt == null || at.isAfter(lastAt))) {
                lastAt = at;
            }
        }

        private long problems() {
            return signals.keySet().stream().filter(PROBLEM_SIGNALS::contains).count();
        }

        private long warnings() {
            return signals.size() - problems();
        }

        private AttentionRow row() {
            List<Signal> ordered = new ArrayList<>();
            SIGNAL_ORDER.forEach(kind -> {
                if (signals.containsKey(kind)) {
                    ordered.add(new Signal(kind, signals.get(kind)));
                }
            });
            return new AttentionRow(user, ordered, lastAt != null ? lastAt.toString() : null, requestId);
        }
    }

    /**
     * N17: the signals of the menus gathered by user: a block in force (its latest state and, from the second, how
     * often), an administrator without MFA, a lock, three or more consecutive failed logins, three or more step-ups in
     * the period. The users with more problem signals come first, then more warnings, then the latest signal.
     */
    AttentionPart attention(String period, Instant now) {
        Map<String, Gathered> users = new LinkedHashMap<>();
        boolean capped = false;
        List<BlockRow> blocks = sources.queries().blocksInForce(ATTENTION_READ);
        capped |= blocks.size() >= ATTENTION_READ;
        for (BlockRow block : blocks) {
            Gathered user = gathered(users, block.username() != null && !block.username().isBlank() ? block.username()
                    : block.userId());
            user.signal(block.status(), null, block.blockedAt());
            if (block.blockCount() >= 2) {
                user.signal("REPEATED", (long) block.blockCount(), null);
            }
            if (user.requestId == null) {
                user.requestId = block.requestId();
            }
        }
        List<String> admins = sources.administrators().administratorsWithoutMfa(ATTENTION_READ);
        capped |= admins.size() >= ATTENTION_READ;
        admins.forEach(name -> gathered(users, name).signal("ADMIN_NO_MFA", null, null));
        List<AccountSignal> accounts = sources.queries().accountSignals(now, ATTENTION_READ);
        capped |= accounts.size() >= ATTENTION_READ;
        for (AccountSignal account : accounts) {
            Gathered user = gathered(users, account.username());
            if (account.locked()) {
                user.signal("LOCKED", null, account.lastFailureAt());
            }
            if (account.failedAttempts() >= DashboardQueries.LOGIN_FAILURES_AT_LEAST) {
                user.signal("LOGIN_FAILURES", (long) account.failedAttempts(), account.lastFailureAt());
            }
        }
        List<UserChallenges> challenged = sources.console().challengedAtLeast(period, CHALLENGES_AT_LEAST,
                ATTENTION_READ);
        capped |= challenged.size() >= ATTENTION_READ;
        for (UserChallenges user : challenged) {
            gathered(users, user.user()).signal("CHALLENGES", user.challenges(), parse(user.lastAt()));
        }
        List<AttentionRow> rows = users.values().stream()
                .sorted(Comparator.comparingLong(Gathered::problems).reversed()
                        .thenComparing(Comparator.comparingLong(Gathered::warnings).reversed())
                        .thenComparing(user -> user.lastAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(user -> user.user))
                .limit(ATTENTION_SHOWN).map(Gathered::row).toList();
        return new AttentionPart(users.size(), capped, rows);
    }

    /** The user of the name; the spellings of one name differ in case only and are one user. */
    private static Gathered gathered(Map<String, Gathered> users, String name) {
        String shown = name == null ? "" : name.trim();
        return users.computeIfAbsent(shown.toLowerCase(Locale.ROOT), key -> new Gathered(shown));
    }

    // ----- the recent admin changes (N19, N21) -----

    ChangesPart changes(Instant from, Instant to, Locale locale) {
        List<Count> byKind = new ArrayList<>();
        sources.queries().changesByKind(from, to).forEach((kind, count) -> byKind.add(new Count(kind, count)));
        byKind.sort(Comparator.comparingLong(Count::count).reversed());
        List<ChangeRow> recent = new ArrayList<>();
        for (ChangeRecord change : sources.queries().recentChanges(from, to, CHANGES_SHOWN)) {
            String kind = DashboardQueries.CHANGE_KINDS.get(change.category());
            recent.add(new ChangeRow(change.at() != null ? change.at().toString() : null, actorOf(change, locale),
                    kind, actionOf(kind, change), targetOf(kind, change, locale)));
        }
        return new ChangesPart(byKind, recent);
    }

    /** The words key of the change, or null when the timeline names it by its kind. */
    static String actionOf(String kind, ChangeRecord change) {
        String action = change.action();
        String key = switch (kind == null ? "" : kind) {
            case "POLICY" -> DefaultPolicyService.APPROVED.equals(action) ? "POLICY_APPROVED"
                    : DefaultPolicyService.REJECTED.equals(action) ? "POLICY_REJECTED" : change.category();
            case "ROLE" -> change.category();
            case "MODE" -> "ZERO_TRUST_MODE_CHANGED";
            case "USER" -> action != null && action.startsWith("USER_") ? action : change.category();
            case "AGENT" -> "AGENT_KILL_SWITCH".equals(change.category()) || "AGENT_RELEASED".equals(change.category())
                    ? action : change.category();
            default -> action;
        };
        return key != null && NAMED_ACTIONS.contains(key) ? key : null;
    }

    /** K109: who made the change; a version registered from a node's document folder reads as the document folder. */
    String actorOf(ChangeRecord change, Locale locale) {
        String actor = change.actor();
        return actor != null && actor.startsWith(PromptVersionAudit.FOLDER_ACTOR)
                ? message(FOLDER_ACTOR_WORDS, "Document folder", locale) : actor;
    }

    /** What the change was made to, in words: a role by its description, a prompt by its name, a mode by its code. */
    String targetOf(String kind, ChangeRecord change, Locale locale) {
        String resource = change.resource();
        if ("MODE".equals(kind)) {
            return change.decision();
        }
        if ("ROLE".equals(kind) && resource != null) {
            return sources.roles().findByRoleName(resource).map(Role::getRoleDesc).filter(text -> !text.isBlank())
                    .orElse(resource.startsWith("ROLE_") ? resource.substring("ROLE_".length()) : resource);
        }
        if ("PROMPT".equals(kind) && resource != null && resource.contains("@")) {
            int at = resource.lastIndexOf('@');
            String prompt = resource.substring(0, at);
            String other = message("pv.prompt.other", prompt, locale);
            return message("pv.prompt." + prompt, other, locale) + " " + resource.substring(at + 1);
        }
        return resource;
    }

    private String message(String key, String fallback, Locale locale) {
        return sources.messages() != null ? sources.messages().getMessage(key, null, fallback,
                locale != null ? locale : Locale.ENGLISH) : fallback;
    }

    // ----- the most refused access (N20) -----

    private DenialsPart denials(Instant from, Instant to) {
        return new DenialsPart(sources.queries().denials(from, to),
                sources.queries().topDenials(DashboardHourlyStats.RESOURCE, from, to, DENIALS_RANKED),
                sources.queries().topDenials(DashboardHourlyStats.USER, from, to, DENIALS_RANKED));
    }

    // ----- helpers -----

    /** The first of the days shown, today the last. */
    private static LocalDate firstDay(Instant now) {
        return LocalDate.ofInstant(now, ZoneId.systemDefault()).minusDays(DAYS_SHOWN - 1L);
    }

    private static Instant start(LocalDate day) {
        return day.atStartOfDay(ZoneId.systemDefault()).toInstant();
    }

    private static LocalDateTime local(Instant moment) {
        return LocalDateTime.ofInstant(moment, ZoneId.systemDefault());
    }

    @Nullable
    private static Instant parse(@Nullable String moment) {
        try {
            return moment == null || "null".equals(moment) ? null : Instant.parse(moment);
        } catch (RuntimeException unreadable) {
            return null;
        }
    }
}
