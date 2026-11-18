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

import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.web.auth.service.AccountsOfPeople;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Count;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DayCount;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The dashboard's own reads of the console's tables (plan step 9, N3 to N20): counts in one statement each, so the
 * dashboard never loads the rows it counts. The accounts of people are the enabled ones of Contexa's own that are no
 * agent's: a bridge copy of an application's user and an agent's account are left out. The audit log keeps local times,
 * so a period's instants are passed as timestamps of the server's zone, as every audit read does.
 */
public class DashboardQueries {

    /** The consecutive failed logins from which a user is one to look at (the approved rule: three). */
    public static final int LOGIN_FAILURES_AT_LEAST = 3;

    /** The categories of the admin changes and the kind each belongs to (N19). */
    static final Map<String, String> CHANGE_KINDS = changeKinds();

    /** A failed automatic policy synchronisation is recorded under POLICY_CREATED: it changed nothing. */
    static final String AUTO_POLICY_SYNC_BLOCKED = "AUTO_POLICY_SYNC_BLOCKED";

    /**
     * K109: the names, in lower case, the system's own records of those categories are written under: SYSTEM where no
     * one is signed in (the role, user and policy services at start and the policy synchronisation), system (a prompt
     * version record without an actor) and the product's prompt versions registered at start. A version registered from
     * a node's document folder ({@link PromptVersionAudit#FOLDER_ACTOR} and the node) is an operator's: the operator put
     * its document there.
     */
    static final List<String> SYSTEM_ACTORS = List.of("system", PromptVersionAudit.PRODUCT_ACTOR);

    /**
     * K114: what a version made from a document is recorded under beside its creation: registered from the folder,
     * imported on the screen. The two records of one version are one change, read by the second.
     */
    static final List<String> VERSION_FROM_A_DOCUMENT = List.of(PromptVersionAudit.FOLDER_REGISTERED,
            PromptVersionAudit.IMPORTED);

    /**
     * What makes a record of those categories an admin change (N19, K109, K114): a refused administrator change, a
     * failed policy synchronisation, a record the system wrote on its own, or under no name, and the creation of a
     * version that is recorded again as made from a document (by the same actor) are none.
     */
    private static final String ADMIN_CHANGE = """
               AND NOT (a.event_category = 'ADMIN_OVERRIDE' AND COALESCE(a.outcome, '') = 'REFUSED')
               AND COALESCE(a.action, '') <> '%s'
               AND LOWER(TRIM(COALESCE(a.principal_name, ''))) NOT IN ('', %s)
               AND NOT (a.event_category = 'PROMPT_VERSION_CHANGED' AND a.action = '%s' AND EXISTS (
                   SELECT 1 FROM ctxa_audit_log d
                    WHERE d.event_category = a.event_category AND d.action IN (%s)
                      AND d.resource_identifier = a.resource_identifier AND d.principal_name = a.principal_name))
            """.formatted(AUTO_POLICY_SYNC_BLOCKED, quoted(SYSTEM_ACTORS), PromptVersionAudit.CREATED,
            quoted(VERSION_FROM_A_DOCUMENT));

    /** K92: the accounts of people as the list of users filters them too. */
    private static final String ACCOUNTS_OF_PEOPLE = AccountsOfPeople.CONDITION;
    private static final String AGENT_MAIL = AccountsOfPeople.AGENT_MAIL;

    /** Every user's latest block record, a record that keeps the block before a resolved one of the same time. */
    private static final String LATEST_BLOCKS = """
            SELECT DISTINCT ON (b.user_id) b.user_id, b.username, b.status, b.blocked_at, b.block_count, b.request_id
              FROM ctxa_blocked_user b
             WHERE b.user_id IS NOT NULL AND b.user_id <> ''
             ORDER BY b.user_id, b.blocked_at DESC, CASE WHEN b.status = 'RESOLVED' THEN 1 ELSE 0 END, b.id DESC
            """;

    /** The admin changes of a period. */
    private static final String CHANGES_OF_PERIOD = """
             WHERE a.timestamp >= ? AND a.timestamp < ? AND a.event_category IN (%s)
            """.formatted(quoted(CHANGE_KINDS.keySet())) + ADMIN_CHANGE;

    private final Supplier<JdbcOperations> jdbc;

    public DashboardQueries(Supplier<JdbcOperations> jdbc) {
        this.jdbc = jdbc != null ? jdbc : () -> null;
    }

    private static Map<String, String> changeKinds() {
        Map<String, String> kinds = new LinkedHashMap<>();
        for (String category : List.of("POLICY_CREATED", "POLICY_UPDATED", "POLICY_DELETED")) {
            kinds.put(category, "POLICY");
        }
        for (String category : List.of("USER_CREATED", "USER_MODIFIED", "USER_DELETED")) {
            kinds.put(category, "USER");
        }
        for (String category : List.of("ROLE_CREATED", "ROLE_UPDATED", "ROLE_DELETED")) {
            kinds.put(category, "ROLE");
        }
        // K75: the changes of the console that had no audit record before
        for (String category : List.of("GROUP_CREATED", "GROUP_UPDATED", "GROUP_DELETED")) {
            kinds.put(category, "GROUP");
        }
        for (String category : List.of("PERMISSION_CREATED", "PERMISSION_UPDATED", "PERMISSION_DELETED")) {
            kinds.put(category, "PERMISSION");
        }
        kinds.put("ROLE_HIERARCHY_CHANGED", "HIERARCHY");
        kinds.put("ROLE_ASSIGNMENT_CHANGED", "ASSIGNMENT");
        kinds.put("PASSWORD_POLICY_CHANGED", "PASSWORD");
        kinds.put("MENU_CHANGED", "MENU");
        kinds.put("SYSTEM_SETTINGS_CHANGED", "SETTINGS");
        // K130: the other changes of the console that had no audit record
        kinds.put("IP_ACCESS_RULE_CHANGED", "IP");
        kinds.put("SESSION_INVALIDATED", "SESSION");
        kinds.put("RESOURCE_MANAGEMENT_CHANGED", "RESOURCE");
        kinds.put("BLOCK_RECORD_DELETED", "BLOCK");
        kinds.put("CONDITION_TEMPLATE_CHANGED", "CONDITION");
        kinds.put("PROMPT_VERSION_CHANGED", "PROMPT");
        kinds.put("ZERO_TRUST_MODE_CHANGED", "MODE");
        kinds.put("ADMIN_OVERRIDE", "OVERRIDE");
        for (String category : List.of("AGENT_REGISTERED", "AGENT_DEREGISTERED", "AGENT_REMOVED", "AGENT_SPONSOR_CHANGED",
                "AGENT_SECRET_ROTATED", "AGENT_RELEASED", "AGENT_KILL_SWITCH", "AGENT_LEARNING_CONTROLLED")) {
            kinds.put(category, "AGENT");
        }
        return Collections.unmodifiableMap(kinds);
    }

    private static String quoted(Collection<String> values) {
        return String.join(", ", values.stream().map(value -> "'" + value + "'").toList());
    }

    // ----- accounts (N3, N4, N18) -----

    /** The enabled accounts of people now, and how many of them use MFA, are locked, dormant or past their password. */
    public record Accounts(long active, long mfaEnabled, long locked, long dormant, long expired) {
    }

    /**
     * @param dormantBefore       an account whose latest sign-in (its creation when it never signed in) is before it is
     *                            dormant
     * @param passwordChangedBefore an account whose password changed before it is past its password; null when the
     *                              policy lets passwords live for ever
     */
    public Accounts accounts(Instant now, Instant dormantBefore, @Nullable Instant passwordChangedBefore) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return new Accounts(0, 0, 0, 0, 0);
        }
        return operations.queryForObject("SELECT COUNT(*), COUNT(*) FILTER (WHERE u.mfa_enabled = TRUE), "
                        + "COUNT(*) FILTER (WHERE " + AccountsOfPeople.LOCKED + "), "
                        + "COUNT(*) FILTER (WHERE " + AccountsOfPeople.DORMANT + "), "
                        + "COUNT(*) FILTER (WHERE ? AND u.password_changed_at IS NOT NULL AND u.password_changed_at < ?) "
                        + "FROM ctxa_users u WHERE " + ACCOUNTS_OF_PEOPLE,
                (rs, row) -> new Accounts(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4), rs.getLong(5)),
                timestamp(now), timestamp(dormantBefore), passwordChangedBefore != null,
                timestamp(passwordChangedBefore != null ? passwordChangedBefore : now), AGENT_MAIL);
    }

    /** An account of a person locked now, or with consecutive failed logins, and when the latest failure was. */
    public record AccountSignal(String username, int failedAttempts, boolean locked, @Nullable Instant lastFailureAt) {
    }

    /**
     * N18: the accounts of people locked now or with at least {@link #LOGIN_FAILURES_AT_LEAST} consecutive failed logins,
     * the most failures first, at most {@code limit}; each with its latest failed authentication in the audit log.
     */
    public List<AccountSignal> accountSignals(Instant now, int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || limit <= 0) {
            return List.of();
        }
        List<AccountSignal> accounts = operations.query("SELECT u.username, u.failed_login_attempts, ("
                        + AccountsOfPeople.LOCKED + ") AS locked FROM ctxa_users u WHERE " + ACCOUNTS_OF_PEOPLE
                        + " AND ((" + AccountsOfPeople.LOCKED + ") OR u.failed_login_attempts >= ?)"
                        + " ORDER BY u.failed_login_attempts DESC, u.username LIMIT ?",
                (rs, row) -> new AccountSignal(rs.getString(1), rs.getInt(2), rs.getBoolean(3), null),
                timestamp(now), AGENT_MAIL, timestamp(now), LOGIN_FAILURES_AT_LEAST, limit);
        if (accounts.isEmpty()) {
            return accounts;
        }
        Map<String, Instant> last = lastFailures(accounts.stream().map(AccountSignal::username).toList());
        return accounts.stream().map(account -> new AccountSignal(account.username(), account.failedAttempts(),
                account.locked(), last.get(account.username()))).toList();
    }

    /** The latest failed authentication of each name, in one read of the failures. */
    Map<String, Instant> lastFailures(Collection<String> usernames) {
        JdbcOperations operations = jdbc.get();
        Map<String, Instant> last = new LinkedHashMap<>();
        if (operations == null || usernames.isEmpty()) {
            return last;
        }
        List<Object> args = new ArrayList<>(usernames);
        String marks = String.join(", ", Collections.nCopies(usernames.size(), "?"));
        operations.query("SELECT a.principal_name, MAX(a.timestamp) FROM ctxa_audit_log a "
                + "WHERE a.event_category = 'AUTHENTICATION_FAILURE' AND a.principal_name IN (" + marks + ") "
                + "GROUP BY a.principal_name", (ResultSet rs) -> {
                    Instant at = instant(rs.getTimestamp(2));
                    if (at != null) {
                        last.put(rs.getString(1), at);
                    }
                }, args.toArray());
        return last;
    }

    // ----- blocks (N6) -----

    /** A user's block in force: the latest record of the user, not resolved. */
    public record BlockRow(String userId, @Nullable String username, String status, @Nullable Instant blockedAt,
                           int blockCount, @Nullable String requestId) {
    }

    /** How many users are blocked now, by the state of the latest record of each, as the block list holds them. */
    public Map<String, Long> blocksByLatestStatus() {
        JdbcOperations operations = jdbc.get();
        Map<String, Long> counts = new LinkedHashMap<>();
        if (operations == null) {
            return counts;
        }
        operations.query("SELECT l.status, COUNT(*) FROM (" + LATEST_BLOCKS + ") l WHERE l.status <> 'RESOLVED' "
                + "GROUP BY l.status", (ResultSet rs) -> {
                    counts.put(rs.getString(1), rs.getLong(2));
                });
        return counts;
    }

    /** The users blocked now, the latest block first, at most {@code limit}. */
    public List<BlockRow> blocksInForce(int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || limit <= 0) {
            return List.of();
        }
        return operations.query("SELECT * FROM (" + LATEST_BLOCKS + ") l WHERE l.status <> 'RESOLVED' "
                        + "ORDER BY l.blocked_at DESC, l.user_id LIMIT ?",
                (rs, row) -> new BlockRow(rs.getString("user_id"), rs.getString("username"), rs.getString("status"),
                        instant(rs.getTimestamp("blocked_at")), rs.getInt("block_count"), rs.getString("request_id")),
                limit);
    }

    // ----- sessions (N8) -----

    /** The sessions used since the moment: a session that ended without being marked is not counted once idle. */
    public long sessionsSince(Instant since) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        Long count = operations.queryForObject("SELECT COUNT(*) FROM ctxa_active_sessions s "
                + "WHERE s.expired = FALSE AND s.last_accessed_at >= ?", Long.class, timestamp(since));
        return count == null ? 0 : count;
    }

    // ----- the audit log (N14, N15, N16, N19) -----

    /** The audit records of the category in the period. */
    public long count(String category, Instant from, Instant to) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        Long count = operations.queryForObject("SELECT COUNT(*) FROM ctxa_audit_log a WHERE a.event_category = ? "
                + "AND a.timestamp >= ? AND a.timestamp < ?", Long.class, category, timestamp(from), timestamp(to));
        return count == null ? 0 : count;
    }

    /**
     * The audit records of the categories on each day from the first day to the moment, every day listed (0 for a day
     * without one).
     */
    public List<DayCount> byDay(List<String> categories, LocalDate firstDay, Instant firstMoment, Instant to) {
        return byDay(categories, "", firstDay, firstMoment, to);
    }

    /**
     * The admin changes of the categories on each day from the first day to the moment, every day listed, as the recent
     * admin changes count them (K109): a failed policy synchronisation and the system's own records are left out.
     */
    public List<DayCount> changesByDay(List<String> categories, LocalDate firstDay, Instant firstMoment, Instant to) {
        return byDay(categories, ADMIN_CHANGE, firstDay, firstMoment, to);
    }

    private List<DayCount> byDay(List<String> categories, String only, LocalDate firstDay, Instant firstMoment,
                                 Instant to) {
        Map<String, Long> days = new LinkedHashMap<>();
        LocalDate today = LocalDate.ofInstant(to, ZoneId.systemDefault());
        for (LocalDate day = firstDay; !day.isAfter(today); day = day.plusDays(1)) {
            days.put(day.toString(), 0L);
        }
        JdbcOperations operations = jdbc.get();
        if (operations != null && !categories.isEmpty()) {
            List<Object> args = new ArrayList<>(categories);
            args.add(timestamp(firstMoment));
            args.add(timestamp(to));
            String marks = String.join(", ", Collections.nCopies(categories.size(), "?"));
            operations.query("SELECT CAST(a.timestamp AS DATE), COUNT(*) FROM ctxa_audit_log a "
                    + "WHERE a.event_category IN (" + marks + ") AND a.timestamp >= ? AND a.timestamp < ? " + only
                    + " GROUP BY 1", (ResultSet rs) -> {
                        String day = String.valueOf(rs.getDate(1));
                        long count = rs.getLong(2);
                        days.computeIfPresent(day, (key, zero) -> count);
                    }, args.toArray());
        }
        List<DayCount> counts = new ArrayList<>();
        days.forEach((day, count) -> counts.add(new DayCount(day, count)));
        return counts;
    }

    /** How often an agent alarm of the category came in the period, and the latest time. */
    public record Alarm(long count, @Nullable Instant lastAt) {
    }

    /** N16: the period's records of each of the categories, with the latest time of each. */
    public Map<String, Alarm> alarms(List<String> categories, Instant from, Instant to) {
        Map<String, Alarm> alarms = new LinkedHashMap<>();
        categories.forEach(category -> alarms.put(category, new Alarm(0, null)));
        JdbcOperations operations = jdbc.get();
        if (operations == null || categories.isEmpty()) {
            return alarms;
        }
        List<Object> args = new ArrayList<>(categories);
        args.add(timestamp(from));
        args.add(timestamp(to));
        String marks = String.join(", ", Collections.nCopies(categories.size(), "?"));
        operations.query("SELECT a.event_category, COUNT(*), MAX(a.timestamp) FROM ctxa_audit_log a "
                + "WHERE a.event_category IN (" + marks + ") AND a.timestamp >= ? AND a.timestamp < ? "
                + "GROUP BY a.event_category", (ResultSet rs) -> {
                    alarms.put(rs.getString(1), new Alarm(rs.getLong(2), instant(rs.getTimestamp(3))));
                }, args.toArray());
        return alarms;
    }

    /** An admin change as the audit log keeps it. */
    public record ChangeRecord(Instant at, String actor, String category, @Nullable String action,
                               @Nullable String resource, @Nullable String decision) {
    }

    /** N19: the period's admin changes counted by kind, every kind listed. */
    public Map<String, Long> changesByKind(Instant from, Instant to) {
        Map<String, Long> kinds = new LinkedHashMap<>();
        CHANGE_KINDS.values().forEach(kind -> kinds.putIfAbsent(kind, 0L));
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return kinds;
        }
        operations.query("SELECT a.event_category, COUNT(*) FROM ctxa_audit_log a" + CHANGES_OF_PERIOD
                + " GROUP BY a.event_category", (ResultSet rs) -> {
                    String kind = CHANGE_KINDS.get(rs.getString(1));
                    if (kind != null) {
                        kinds.merge(kind, rs.getLong(2), Long::sum);
                    }
                }, timestamp(from), timestamp(to));
        return kinds;
    }

    /** N19: the period's latest admin changes, the latest first, at most {@code limit}. */
    public List<ChangeRecord> recentChanges(Instant from, Instant to, int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || limit <= 0) {
            return List.of();
        }
        return operations.query("SELECT a.timestamp, a.principal_name, a.event_category, a.action, "
                        + "a.resource_identifier, a.decision FROM ctxa_audit_log a" + CHANGES_OF_PERIOD
                        + " ORDER BY a.timestamp DESC, a.id DESC LIMIT ?",
                (rs, row) -> new ChangeRecord(instant(rs.getTimestamp(1)), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getString(6)), timestamp(from), timestamp(to), limit);
    }

    // ----- the dashboard's hourly tables (N7, N20) -----

    /** N7: the decision records of the period whose seal check found a mismatch, as the hourly pass counted them. */
    public long sealMismatches(Instant from, Instant to) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        Long count = operations.queryForObject("SELECT COALESCE(SUM(s.mismatched), 0) FROM ctxa_dashboard_seal_hourly s "
                + "WHERE s.bucket_start >= ? AND s.bucket_start < ?", Long.class, hour(from), timestamp(to));
        return count == null ? 0 : count;
    }

    /** K92: the decision records the hourly seal check found mismatched, the ones still kept, written since the moment. */
    private static final String SEAL_MISMATCH_RECORDS = " FROM ctxa_audit_log a "
            + "JOIN ctxa_dashboard_seal_mismatch m ON m.audit_id = a.id WHERE a.timestamp >= ?";

    /** K92: how many records {@link #sealMismatchRecordIds} lists. */
    public long sealMismatchRecordCount(LocalDateTime since) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        Long count = operations.queryForObject("SELECT COUNT(*)" + SEAL_MISMATCH_RECORDS, Long.class,
                Timestamp.valueOf(since));
        return count == null ? 0 : count;
    }

    /**
     * K92: a page of the decision records the hourly seal check found mismatched, written since the moment (a local
     * time, as the audit log keeps it), the latest first: the records of {@link #sealMismatches} the audit log keeps.
     */
    public List<Long> sealMismatchRecordIds(LocalDateTime since, long offset, int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || limit <= 0) {
            return List.of();
        }
        return operations.queryForList("SELECT a.id" + SEAL_MISMATCH_RECORDS
                + " ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?", Long.class, Timestamp.valueOf(since), limit,
                offset);
    }

    /** N20: the refused requests of signed-in users in the period. */
    public long denials(Instant from, Instant to) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return 0;
        }
        Long count = operations.queryForObject("SELECT COALESCE(SUM(d.counted), 0) FROM ctxa_dashboard_denial_hourly d "
                + "WHERE d.dimension = ? AND d.bucket_start >= ? AND d.bucket_start < ?", Long.class,
                DashboardHourlyStats.RESOURCE, hour(from), timestamp(to));
        return count == null ? 0 : count;
    }

    /** N20: the resources or the users refused most in the period, the most first and a tie by name. */
    public List<Count> topDenials(String dimension, Instant from, Instant to, int limit) {
        JdbcOperations operations = jdbc.get();
        if (operations == null || limit <= 0) {
            return List.of();
        }
        return operations.query("SELECT d.item, SUM(d.counted) FROM ctxa_dashboard_denial_hourly d "
                        + "WHERE d.dimension = ? AND d.bucket_start >= ? AND d.bucket_start < ? "
                        + "GROUP BY d.item ORDER BY SUM(d.counted) DESC, d.item LIMIT ?",
                (rs, row) -> new Count(rs.getString(1), rs.getLong(2)), dimension.toUpperCase(Locale.ROOT),
                hour(from), timestamp(to), limit);
    }

    // ----- helpers -----

    /** The start of the hour the moment is in: the hourly tables count whole hours, as the console's do. */
    static Timestamp hour(Instant moment) {
        return Timestamp.from(moment.truncatedTo(ChronoUnit.HOURS));
    }

    static Timestamp timestamp(Instant moment) {
        return moment == null ? null : Timestamp.from(moment);
    }

    @Nullable
    static Instant instant(@Nullable Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

}
