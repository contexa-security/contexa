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
package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.agent.AgentStatus;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Count;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DayCount;
import io.contexa.contexaiam.admin.web.dashboard.DashboardHourlyStats;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.AccountSignal;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.Accounts;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.BlockRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.ChangeRecord;
import io.contexa.contexaiam.admin.web.monitoring.controller.SecurityMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.dto.DecisionRecordIntegrity;
import io.contexa.contexaiam.admin.web.monitoring.service.DecisionRecordSealCheck;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.UserChallenges;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import io.contexa.contexaiam.agent.JdbcAgentConfirmationStore;
import io.contexa.contexaiam.agent.JdbcAgentRegistry;
import io.contexa.contexaiam.agent.JdbcDelegationRegistry;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Plan step 9 on a real PostgreSQL database: every number the dashboard counts in one statement, against rows whose
 * numbers are known. The administrators by ROLE_ADMIN (K72), the accounts of people, the deny rules in force (K74), the
 * blocks by their latest state, the agents, the admin changes, the refusals and the seal checks by hour with what is
 * written late, the step-ups of the period, and the permissions nothing uses.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class DashboardPostgresTest {

    private static PostgresTestDatabase database;
    private static LocalContainerEntityManagerFactoryBean entityManagers;
    private static JdbcTemplate jdbc;
    private static RoleHierarchyImpl hierarchy;
    private static LastAdministratorGuard guard;
    private static AuditLogRepository auditLog;
    private static PermissionRepository permissions;
    private static IpAccessRuleRepository ipRules;

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS).plus(Duration.ofMinutes(30));
    private final MovableClock clock = new MovableClock(now);
    private final DashboardQueries queries = new DashboardQueries(() -> jdbc);

    @BeforeAll
    static void aConsoleOnTheCanonicalSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa-dashboard");
        entityManagers.setPackagesToScan("io.contexa.contexacommon.entity", "io.contexa.contexaiam.domain.entity");
        entityManagers.setJpaPropertyMap(Map.of(
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy",
                "hibernate.implicit_naming_strategy",
                "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        entityManagers.afterPropertiesSet();
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagers.getObject());
        JpaRepositoryFactory repositories = new JpaRepositoryFactory(entityManager);
        UserRepository users = repositories.getRepository(UserRepository.class);
        RoleRepository roles = repositories.getRepository(RoleRepository.class);
        auditLog = repositories.getRepository(AuditLogRepository.class);
        permissions = repositories.getRepository(PermissionRepository.class);
        ipRules = repositories.getRepository(IpAccessRuleRepository.class);
        hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("");
        guard = new LastAdministratorGuard(users, roles, hierarchy, null);
    }

    @AfterAll
    static void close() {
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void anEmptyConsole() {
        jdbc.execute("truncate ctxa_user_roles, ctxa_user_groups, ctxa_group_roles, ctxa_users, ctxa_role, "
                + "ctxa_app_group, ctxa_permission, ctxa_role_permissions, ctxa_audit_log, ctxa_blocked_user, "
                + "ctxa_active_sessions, ctxa_ip_access_rules, ctxa_agent_registration, ctxa_agent_delegation_record, "
                + "ctxa_agent_confirmation, ctxa_zt_item_hourly, ctxa_dashboard_denial_hourly, "
                + "ctxa_dashboard_seal_hourly, ctxa_managed_resource, ctxa_ai_security_decision_observation "
                + "restart identity cascade");
        hierarchy.setHierarchy("");
    }

    // ----- N2, K72: the administrators are the holders of ROLE_ADMIN -----

    @Test
    @DisplayName("N2: the administrators are the enabled own accounts that hold ROLE_ADMIN, the hierarchy included")
    void theAdministratorsAreTheHoldersOfRoleAdmin() {
        long admin = role("ROLE_ADMIN");
        long named = role("ADMIN");
        long auditor = role("ROLE_AUDITOR");
        long superRole = role("ROLE_SUPER");
        long ops = group("ops", admin);
        userRole(user("direct.admin", false), admin);
        userGroup(user("group.admin", true), ops);
        userRole(user("super.admin", false), superRole);
        // A role named ADMIN grants ROLE_ADMIN at the sign-in, as the console reads role names; another role none.
        userRole(user("named.admin", false), named);
        userRole(user("auditor", false), auditor);
        long disabled = user("disabled.admin", false);
        jdbc.update("update ctxa_users set enabled = false where id = ?", disabled);
        userRole(disabled, admin);
        long bridged = user("bridged.admin", false);
        jdbc.update("update ctxa_users set bridge_managed = true where id = ?", bridged);
        userRole(bridged, admin);
        hierarchy.setHierarchy("ROLE_SUPER > ROLE_ADMIN");

        assertThat(guard.administratorCount()).isEqualTo(4);
        assertThat(guard.administratorsWithoutMfaCount()).isEqualTo(3);
        assertThat(guard.administratorsWithoutMfa(10)).containsExactly("direct.admin", "named.admin", "super.admin");
        assertThat(guard.administratorsWithoutMfa(1)).containsExactly("direct.admin");
    }

    // ----- N3, N4: the accounts of people -----

    @Test
    @DisplayName("N3, N4: MFA, locks, dormancy and expired passwords among the enabled accounts of people")
    void theAccountsOfPeople() {
        long mfa = user("mfa.on", true);
        long locked = user("locked.now", false);
        jdbc.update("update ctxa_users set account_locked = true, lock_expires_at = ? where id = ?",
                at(now.plus(Duration.ofMinutes(10))), locked);
        long lockEnded = user("lock.ended", false);
        jdbc.update("update ctxa_users set account_locked = true, lock_expires_at = ? where id = ?",
                at(now.minus(Duration.ofMinutes(10))), lockEnded);
        long dormant = user("dormant.login", false);
        jdbc.update("update ctxa_users set last_login_at = ? where id = ?", at(now.minus(Duration.ofDays(100))), dormant);
        long neverSigned = user("never.signed", false);
        jdbc.update("update ctxa_users set created_at = ? where id = ?", at(now.minus(Duration.ofDays(120))), neverSigned);
        jdbc.update("update ctxa_users set last_login_at = ?, password_changed_at = ? where id = ?",
                at(now.minus(Duration.ofDays(1))), at(now.minus(Duration.ofDays(100))), mfa);
        // Not accounts of people: a disabled one, a bridge copy, an agent's.
        jdbc.update("update ctxa_users set enabled = false where id = ?", user("disabled", true));
        jdbc.update("update ctxa_users set bridge_managed = true where id = ?", user("bridged", true));
        jdbc.update("update ctxa_users set email = 'report-bot@agents.invalid' where id = ?", user("report-bot", true));

        Accounts accounts = queries.accounts(now, now.minus(Duration.ofDays(90)), now.minus(Duration.ofDays(90)));

        assertThat(accounts.active()).isEqualTo(5);
        assertThat(accounts.mfaEnabled()).isEqualTo(1);
        assertThat(accounts.locked()).isEqualTo(1);
        assertThat(accounts.dormant()).isEqualTo(2);
        assertThat(accounts.expired()).isEqualTo(1);
        // A policy that lets passwords live for ever has none past them.
        assertThat(queries.accounts(now, now.minus(Duration.ofDays(90)), null).expired()).isZero();
    }

    @Test
    @DisplayName("N18: three or more failed logins in a row, or a lock, with the latest failure of the audit log")
    void failedLoginsInARowAndLocksWithTheLatestFailure() {
        jdbc.update("update ctxa_users set failed_login_attempts = 5 where id = ?", user("five.failures", false));
        jdbc.update("update ctxa_users set failed_login_attempts = 3 where id = ?", user("three.failures", false));
        jdbc.update("update ctxa_users set failed_login_attempts = 2 where id = ?", user("two.failures", false));
        long locked = user("locked.one", false);
        jdbc.update("update ctxa_users set failed_login_attempts = 1, account_locked = true, lock_expires_at = ? "
                + "where id = ?", at(now.plus(Duration.ofMinutes(5))), locked);
        audit("AUTHENTICATION_FAILURE", "five.failures", "login", null, null, now.minus(Duration.ofHours(3)));
        audit("AUTHENTICATION_FAILURE", "five.failures", "login", null, null, now.minus(Duration.ofMinutes(20)));

        List<AccountSignal> signals = queries.accountSignals(now, 10);

        assertThat(signals).extracting(AccountSignal::username, AccountSignal::failedAttempts, AccountSignal::locked)
                .containsExactly(tuple("five.failures", 5, false), tuple("three.failures", 3, false),
                        tuple("locked.one", 1, true));
        assertThat(signals.get(0).lastFailureAt()).isEqualTo(now.minus(Duration.ofMinutes(20)));
        assertThat(signals.get(1).lastFailureAt()).isNull();
    }

    // ----- N9, K74: the deny rules in force -----

    @Test
    @DisplayName("N9: an expired deny rule is not one in force, as the filter does not apply it")
    void anExpiredDenyRuleIsNotCounted() {
        LocalDateTime local = LocalDateTime.now();
        ipRule("10.0.0.1", "DENY", true, null);
        ipRule("10.0.0.2", "DENY", true, local.plusDays(1));
        ipRule("10.0.0.3", "DENY", true, local.minusMinutes(1));
        ipRule("10.0.0.4", "DENY", false, null);
        ipRule("10.0.0.5", "ALLOW", true, null);
        ipRule("10.0.0.6", "ALLOW", true, local.minusDays(1));

        IpAccessRuleService service = new IpAccessRuleService(ipRules);

        assertThat(service.countDenyRules()).isEqualTo(2);
        assertThat(service.countAllowRules()).isEqualTo(1);
    }

    // ----- N6: the blocks by their latest state -----

    @Test
    @DisplayName("N6: a user blocked now is counted once, by the state of the latest record")
    void theBlocksByTheirLatestState() {
        block("released", "BLOCKED", now.minus(Duration.ofHours(5)), 1);
        block("released", "RESOLVED", now.minus(Duration.ofHours(4)), 1);
        block("blocked.again", "RESOLVED", now.minus(Duration.ofHours(5)), 1);
        block("blocked.again", "BLOCKED", now.minus(Duration.ofHours(1)), 2);
        block("asked", "UNBLOCK_REQUESTED", now.minus(Duration.ofHours(2)), 1);
        block("failed.mfa", "MFA_FAILED", now.minus(Duration.ofHours(3)), 1);
        block("kept", "TIMEOUT_RESPONDED", now.minus(Duration.ofHours(6)), 1);
        // A resolved record of the same time as a block keeps the block, as the block list holds it.
        block("tie", "RESOLVED", now.minus(Duration.ofHours(7)), 1);
        block("tie", "BLOCKED", now.minus(Duration.ofHours(7)), 1);

        assertThat(queries.blocksByLatestStatus()).containsExactlyInAnyOrderEntriesOf(Map.of("BLOCKED", 2L,
                "UNBLOCK_REQUESTED", 1L, "MFA_FAILED", 1L, "TIMEOUT_RESPONDED", 1L));
        assertThat(queries.blocksInForce(10)).extracting(BlockRow::username, BlockRow::status, BlockRow::blockCount)
                .containsExactly(tuple("blocked.again", "BLOCKED", 2), tuple("asked", "UNBLOCK_REQUESTED", 1),
                        tuple("failed.mfa", "MFA_FAILED", 1), tuple("kept", "TIMEOUT_RESPONDED", 1),
                        tuple("tie", "BLOCKED", 1));
    }

    // ----- N8: the sessions of the last 30 minutes -----

    @Test
    @DisplayName("N8: the sessions used in the last 30 minutes, an idle or ended one left out")
    void theSessionsOfTheLastHalfHour() {
        session("recent", now.minus(Duration.ofMinutes(10)), false);
        session("idle", now.minus(Duration.ofMinutes(40)), false);
        session("ended", now.minus(Duration.ofMinutes(5)), true);

        assertThat(queries.sessionsSince(now.minus(Duration.ofMinutes(30)))).isEqualTo(1);
    }

    // ----- N10: the agents -----

    @Test
    @DisplayName("N10: the agents by status, the delegations that hold, the confirmations waiting and overdue")
    void theAgentsCountedWhereTheyAreKept() {
        agent("a1", "ACTIVE");
        agent("a2", "ACTIVE");
        agent("s1", "SUSPENDED");
        agent("d1", "DEREGISTERED");
        delegation("holds", now.minus(Duration.ofHours(1)), now.plus(Duration.ofHours(1)), null);
        delegation("expired", now.minus(Duration.ofHours(3)), now.minus(Duration.ofHours(1)), null);
        delegation("revoked", now.minus(Duration.ofHours(3)), now.plus(Duration.ofHours(1)),
                now.minus(Duration.ofMinutes(5)));
        delegation("later", now.plus(Duration.ofHours(1)), now.plus(Duration.ofHours(2)), null);
        confirmation("waiting", "PENDING", now.plus(Duration.ofMinutes(10)));
        confirmation("pending.late", "PENDING", now.minus(Duration.ofMinutes(1)));
        confirmation("approved.unused", "APPROVED", now.minus(Duration.ofMinutes(1)));
        confirmation("rejected", "REJECTED", now.plus(Duration.ofMinutes(10)));

        assertThat(new JdbcAgentRegistry(jdbc).countByStatus(null)).containsExactlyInAnyOrderEntriesOf(Map.of(
                AgentStatus.ACTIVE, 2L, AgentStatus.SUSPENDED, 1L, AgentStatus.DEREGISTERED, 1L));
        assertThat(new JdbcDelegationRegistry(jdbc).countValidAt(now)).isEqualTo(1);
        JdbcAgentConfirmationStore confirmations = new JdbcAgentConfirmationStore(jdbc);
        assertThat(confirmations.countWaiting(now)).isEqualTo(1);
        assertThat(confirmations.countOverdue(now)).isEqualTo(2);
        assertThat(confirmations.countOverdue(now)).isEqualTo(confirmations.overdue(now, 100).size());
    }

    // ----- N14, N15, N19: the audit log -----

    @Test
    @DisplayName("N19: the admin changes by kind and the latest of them, a refusal and a failed synchronisation left out")
    void theAdminChangesOfThePeriod() {
        Instant from = now.minus(Duration.ofDays(7));
        audit("POLICY_UPDATED", "policy.owner", "Payment window", "APPROVED", "SUCCESS", now.minus(Duration.ofHours(1)));
        audit("POLICY_CREATED", "policy.owner", "Export rule", "POLICY_CREATED", "SUCCESS", now.minus(Duration.ofHours(2)));
        audit("POLICY_CREATED", "SYSTEM", "AUTO_POLICY_FOR_PERM_X", "AUTO_POLICY_SYNC_BLOCKED", "CONFLICT",
                now.minus(Duration.ofHours(3)));
        audit("ADMIN_OVERRIDE", "admin", "lee.minseo", "APPROVE", "APPROVED", now.minus(Duration.ofHours(4)));
        audit("ADMIN_OVERRIDE", "admin", "lee.minseo", "RELEASE_CHALLENGE", "REFUSED", now.minus(Duration.ofHours(5)));
        audit("ZERO_TRUST_MODE_CHANGED", "security.lead", "contexa.security.zerotrust.mode", "CHANGE", "APPLIED",
                now.minus(Duration.ofHours(6)));
        audit("USER_MODIFIED", "admin", "yoon.minji", "USER_UNLOCKED", "SUCCESS", now.minus(Duration.ofHours(7)));
        audit("AGENT_KILL_SWITCH", "admin", "*", "KILL_SWITCH_ON", "KILL_SWITCH_ON", now.minus(Duration.ofHours(8)));
        audit("AUTHENTICATION_SUCCESS", "alice", "login", null, "SUCCESS", now.minus(Duration.ofHours(1)));
        audit("ROLE_DELETED", "admin", "ROLE_OLD", "ROLE_DELETED", "SUCCESS", now.minus(Duration.ofDays(9)));

        Map<String, Long> kinds = queries.changesByKind(from, now);
        List<ChangeRecord> recent = queries.recentChanges(from, now, 8);

        assertThat(kinds).containsEntry("POLICY", 2L).containsEntry("OVERRIDE", 1L).containsEntry("MODE", 1L)
                .containsEntry("USER", 1L).containsEntry("AGENT", 1L).containsEntry("ROLE", 0L)
                .containsEntry("PROMPT", 0L);
        assertThat(recent).extracting(ChangeRecord::category, ChangeRecord::action).containsExactly(
                tuple("POLICY_UPDATED", "APPROVED"), tuple("POLICY_CREATED", "POLICY_CREATED"),
                tuple("ADMIN_OVERRIDE", "APPROVE"), tuple("ZERO_TRUST_MODE_CHANGED", "CHANGE"),
                tuple("USER_MODIFIED", "USER_UNLOCKED"), tuple("AGENT_KILL_SWITCH", "KILL_SWITCH_ON"));
        assertThat(recent.get(0).at()).isEqualTo(now.minus(Duration.ofHours(1)));
    }

    @Test
    @DisplayName("K102: the overrides of the period [start, end), a refused one none, the same on the event log")
    void theOverridesOfThePeriodAsTheAdminChangesCountThem() {
        Instant from = now.minus(Duration.ofDays(7));
        audit("ADMIN_OVERRIDE", "admin", "lee.minseo", "APPROVE", "APPROVED", now.minus(Duration.ofHours(4)));
        audit("ADMIN_OVERRIDE", "admin", "lee.minseo", "RELEASE_CHALLENGE", "REFUSED", now.minus(Duration.ofHours(5)));
        audit("ADMIN_OVERRIDE", "admin", "kim.sora", "APPROVE", "APPROVED", now.minus(Duration.ofDays(8)));
        audit("ADMIN_OVERRIDE", "admin", "kim.sora", "APPROVE", "APPROVED", now.plus(Duration.ofDays(1)));

        long dashboard = auditLog.countAdminOverridesBetween(local(from), local(now));
        Model model = new ExtendedModelMap();
        new SecurityMonitorController(auditLog, null).monitor(null, null, null, null, 168, from.toString(), 0, model);

        assertThat(dashboard).isEqualTo(1);
        assertThat(model.getAttribute("adminOverride")).isEqualTo(dashboard);
        assertThat(queries.changesByKind(from, now)).containsEntry("OVERRIDE", dashboard);
    }

    @Test
    @DisplayName("N14, N15: the records of each of the last seven days, every day listed")
    void theRecordsOfEachDay() {
        LocalDate today = LocalDate.ofInstant(now, ZoneId.systemDefault());
        LocalDate first = today.minusDays(6);
        Instant start = first.atStartOfDay(ZoneId.systemDefault()).toInstant();
        audit("AUTHENTICATION_FAILURE", "alice", "login", null, null, now.minus(Duration.ofMinutes(1)));
        audit("AUTHENTICATION_FAILURE", "bob", "login", null, null, now.minus(Duration.ofMinutes(2)));
        audit("AUTHENTICATION_FAILURE", "bob", "login", null, null, start.plus(Duration.ofHours(1)));
        audit("AUTHENTICATION_FAILURE", "bob", "login", null, null, start.minus(Duration.ofHours(1)));
        audit("POLICY_UPDATED", "owner", "p", "POLICY_UPDATED", "SUCCESS", now.minus(Duration.ofMinutes(1)));
        audit("POLICY_CREATED", "SYSTEM", "p", "AUTO_POLICY_SYNC_BLOCKED", "CONFLICT", now.minus(Duration.ofMinutes(1)));

        List<DayCount> failures = queries.byDay(List.of("AUTHENTICATION_FAILURE"), first, start, now);
        List<DayCount> changes = queries.byDay(List.of("POLICY_CREATED", "POLICY_UPDATED", "POLICY_DELETED"), first,
                start, now);

        assertThat(failures).hasSize(7);
        assertThat(failures.get(0)).isEqualTo(new DayCount(first.toString(), 1));
        // The test's moment is half past an hour: a minute or two before it is the same day.
        assertThat(failures.get(6)).isEqualTo(new DayCount(today.toString(), 2));
        assertThat(failures.stream().mapToLong(DayCount::count).sum()).isEqualTo(3);
        assertThat(changes.stream().mapToLong(DayCount::count).sum()).isEqualTo(1);
        assertThat(queries.count("AUTHENTICATION_FAILURE", now.minus(Duration.ofDays(1)), now)).isEqualTo(2);
    }

    // ----- N20: the refusals of signed-in users, by hour, and what is written late -----

    @Test
    @DisplayName("N20: the refusals of signed-in users by resource and by user, a late record reaching its hour")
    void theRefusalsByHourWithTheLateRecords() {
        Instant hour = now.minus(Duration.ofHours(2));
        for (int i = 0; i < 3; i++) {
            denied("alice", "/api/a", hour);
        }
        denied("bob", "/api/a", hour);
        denied("alice", "/api/b", hour);
        for (int i = 0; i < 5; i++) {
            denied("anonymousUser", "/api/a", hour);
        }
        audit("AUTHORIZATION_GRANTED", "alice", "/api/a", null, "GRANTED", hour);
        // A refusal of 20 days ago, older than the first pass's two days: the first pass fills its hour later.
        denied("carol", "/api/old", now.minus(Duration.ofDays(20)));
        DashboardHourlyStats stats = new DashboardHourlyStats(() -> jdbc, null, null, null, clock);

        stats.rebuildOnce();
        Instant weekAgo = now.minus(Duration.ofDays(7));

        assertThat(queries.denials(weekAgo, now)).isEqualTo(5);
        assertThat(queries.topDenials(DashboardHourlyStats.RESOURCE, weekAgo, now, 5)).extracting(Count::key, Count::count)
                .containsExactly(tuple("/api/a", 4L), tuple("/api/b", 1L));
        assertThat(queries.topDenials(DashboardHourlyStats.USER, weekAgo, now, 5)).extracting(Count::key, Count::count)
                .containsExactly(tuple("alice", 4L), tuple("bob", 1L));
        assertThat(queries.denials(now.minus(Duration.ofDays(30)), now)).isEqualTo(6);

        // A refusal written after its hour was rebuilt: the next pass rebuilds that hour.
        denied("bob", "/api/a", now.minus(Duration.ofHours(5)));
        clock.move(Duration.ofMinutes(1));
        stats.rebuildOnce();

        assertThat(queries.denials(weekAgo, now.plus(Duration.ofMinutes(1)))).isEqualTo(6);
        assertThat(queries.topDenials(DashboardHourlyStats.USER, weekAgo, now.plus(Duration.ofMinutes(1)), 5))
                .extracting(Count::key, Count::count).containsExactly(tuple("alice", 4L), tuple("bob", 2L));
    }

    // ----- N7: the seal checks by hour, and a record changed after its hour was checked -----

    @Test
    @DisplayName("N7: a broken seal is counted by the hourly pass, and found again when its hour is checked again")
    void brokenSealsAreCountedAndFoundAgain() {
        HmacEvidenceSigner signer = new HmacEvidenceSigner(Map.of("k1", "0123456789abcdef0123456789abcdef"
                .getBytes(StandardCharsets.UTF_8)), "k1");
        Instant hour = now.minus(Duration.ofHours(4)).truncatedTo(ChronoUnit.HOURS);
        String previous = null;
        for (int i = 0; i < 3; i++) {
            previous = sealed("decision-" + i, hour.plus(Duration.ofMinutes(10L * (i + 1))), previous, signer);
        }
        DashboardHourlyStats stats = new DashboardHourlyStats(() -> jdbc, auditLog,
                new DecisionRecordSealCheck(auditLog, () -> signer), null, clock);

        stats.rebuildOnce();

        assertThat(queries.sealMismatches(now.minus(Duration.ofDays(1)), now)).isZero();
        assertThat(jdbc.queryForObject("select checked from ctxa_dashboard_seal_hourly where bucket_start = ?",
                Long.class, Timestamp.from(hour))).isEqualTo(3);

        // A decision record changed after its hour was checked: a later pass checks the hour again.
        jdbc.update("update ctxa_audit_log set reason = 'changed afterwards' where resource_identifier = 'decision-1'");
        clock.move(Duration.ofMinutes(2));
        stats.rebuildOnce();

        assertThat(queries.sealMismatches(now.minus(Duration.ofDays(1)), now.plus(Duration.ofMinutes(2)))).isEqualTo(1);
    }

    @Test
    @DisplayName("K103: the broken seals the dashboard counts are the ones the event log lists from the link's start")
    void theBrokenSealsCountedAreTheOnesTheLogLists() {
        HmacEvidenceSigner signer = new HmacEvidenceSigner(Map.of("k1", "0123456789abcdef0123456789abcdef"
                .getBytes(StandardCharsets.UTF_8)), "k1");
        Instant from = now.minus(Duration.ofDays(7));
        Instant hourOfFrom = from.truncatedTo(ChronoUnit.HOURS);
        // one record between the start of the period's first hour and the period's start, one inside the period
        String previous = sealed("on-the-boundary", hourOfFrom.plus(Duration.ofMinutes(10)), null, signer);
        previous = sealed("inside", from.plus(Duration.ofHours(2)), previous, signer);
        sealed("intact", from.plus(Duration.ofHours(3)), previous, signer);
        jdbc.update("update ctxa_audit_log set reason = 'changed afterwards' where resource_identifier <> 'intact'");
        new DashboardHourlyStats(() -> jdbc, auditLog, new DecisionRecordSealCheck(auditLog, () -> signer), null, clock)
                .rebuildOnce();
        SecurityMonitorController monitor = new SecurityMonitorController(auditLog, null);
        monitor.setEvidenceSigner(signer);
        Model model = new ExtendedModelMap();

        long counted = queries.sealMismatches(from, now);
        // the dashboard's link: the decision records from the hour the count starts at
        monitor.monitor("SECURITY_DECISION", null, null, null, 168, hourOfFrom.toString(), 0, model);
        Page<?> page = (Page<?>) model.getAttribute("logPage");
        DecisionRecordIntegrity integrity = (DecisionRecordIntegrity) model.getAttribute("integrity");
        long listed = page.getContent().stream().map(AuditLog.class::cast)
                .filter(record -> "MISMATCH".equals(integrity.of(record.getId()))).count();

        assertThat(counted).isEqualTo(2);
        assertThat(listed).isEqualTo(counted);
        assertThat(model.getAttribute("from")).isEqualTo(hourOfFrom.toString());
    }

    // ----- N17: the step-ups of the period -----

    @Test
    @DisplayName("N17: the users challenged three times or more in the period, from the console's hourly table")
    void theUsersChallengedThreeTimesInThePeriod() {
        Instant first = now.minus(Duration.ofHours(5)).truncatedTo(ChronoUnit.HOURS);
        Instant second = now.minus(Duration.ofHours(2)).truncatedTo(ChronoUnit.HOURS);
        challenges("often", first, 2);
        challenges("often", second, 2);
        challenges("twice", second, 2);
        challenges("long.ago", now.minus(Duration.ofDays(10)).truncatedTo(ChronoUnit.HOURS), 5);
        // K104: the decisions behind the counts; the latest step-up, not its hour, is the user's last signal
        decision("often-1", "often", "CHALLENGE", "FIRST", first.plus(Duration.ofMinutes(5)));
        decision("often-2", "often", "CHALLENGE", "FIRST", second.plus(Duration.ofMinutes(17)));
        decision("often-3", "often", "CHALLENGE", "FIRST", second.plus(Duration.ofMinutes(41)));
        decision("often-retry", "often", "CHALLENGE", "RETRY", second.plus(Duration.ofMinutes(50)));
        decision("often-allowed", "often", "ALLOW", "FIRST", second.plus(Duration.ofMinutes(55)));
        ZeroTrustConsoleService console = new ZeroTrustConsoleService(() -> jdbc, new SecurityZeroTrustProperties(),
                null, new ObjectMapper(), () -> null, false, clock);

        List<UserChallenges> users = console.challengedAtLeast("week", 3, 10);

        assertThat(users).extracting(UserChallenges::user, UserChallenges::challenges).containsExactly(tuple("often", 4L));
        assertThat(Instant.parse(users.get(0).lastAt())).isEqualTo(second.plus(Duration.ofMinutes(41)));
        assertThat(new ZeroTrustDecisionRecords(() -> jdbc, null, null, new ObjectMapper(), clock).reviewPending())
                .isZero();
    }

    // ----- N5: the permissions nothing uses -----

    @Test
    @DisplayName("N5: a permission no resource links and no role carries is a candidate of the unused ones")
    void thePermissionsNothingUses() {
        permission("URL_UNUSED", null);
        long carried = permission("URL_CARRIED", null);
        long resource = jdbc.queryForObject("insert into ctxa_managed_resource (resource_identifier, resource_type) "
                + "values ('/api/x', 'URL') returning id", Long.class);
        permission("URL_LINKED", resource);
        jdbc.update("insert into ctxa_role_permissions (role_id, permission_id) values (?, ?)", role("ROLE_X"), carried);

        assertThat(permissions.findNamesWithoutResourceOrAssignment()).containsExactly("URL_UNUSED");
    }

    // ----- helpers -----

    private static long role(String name) {
        return jdbc.queryForObject("insert into ctxa_role (role_name) values (?) returning role_id", Long.class, name);
    }

    private static long group(String name, long... roleIds) {
        long id = jdbc.queryForObject("insert into ctxa_app_group (group_name) values (?) returning group_id", Long.class,
                name);
        for (long roleId : roleIds) {
            jdbc.update("insert into ctxa_group_roles (group_id, role_id) values (?, ?)", id, roleId);
        }
        return id;
    }

    private static long user(String username, boolean mfa) {
        return jdbc.queryForObject("insert into ctxa_users (username, email, password, name, mfa_enabled) "
                + "values (?, ?, 'x', ?, ?) returning id", Long.class, username, username + "@console.example", username, mfa);
    }

    private static void userGroup(long userId, long groupId) {
        jdbc.update("insert into ctxa_user_groups (user_id, group_id) values (?, ?)", userId, groupId);
    }

    private static void userRole(long userId, long roleId) {
        jdbc.update("insert into ctxa_user_roles (user_id, role_id, assigned_at) values (?, ?, current_timestamp)", userId,
                roleId);
    }

    private static long permission(String name, Long resourceId) {
        return jdbc.queryForObject("insert into ctxa_permission (permission_name, managed_resource_id) values (?, ?) "
                + "returning permission_id", Long.class, name, resourceId);
    }

    private static Timestamp at(Instant moment) {
        return Timestamp.from(moment);
    }

    private static void audit(String category, String principal, String resource, String action, String outcome,
                              Instant moment) {
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision, "
                + "outcome, event_category) values (?, ?, ?, ?, 'SUCCESS', ?, ?)", at(moment), principal, resource,
                action, outcome, category);
    }

    private static void denied(String principal, String resource, Instant moment) {
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, request_uri, decision, "
                + "outcome, event_category) values (?, ?, ?, ?, 'DENY', 'DENIED', 'AUTHORIZATION_DENIED')", at(moment),
                principal, resource, resource);
    }

    private static void ipRule(String address, String type, boolean enabled, LocalDateTime expiresAt) {
        jdbc.update("insert into ctxa_ip_access_rules (created_at, enabled, expires_at, ip_address, rule_type) "
                + "values (current_timestamp, ?, ?, ?, ?)", enabled, expiresAt == null ? null : Timestamp.valueOf(expiresAt),
                address, type);
    }

    private static void block(String user, String status, Instant moment, int count) {
        jdbc.update("insert into ctxa_blocked_user (user_id, username, request_id, blocked_at, block_count, status) "
                + "values (?, ?, ?, ?, ?, ?)", user, user, user + "-" + status + "-" + moment.toEpochMilli(), at(moment),
                count, status);
    }

    private static void session(String id, Instant lastAccess, boolean expired) {
        jdbc.update("insert into ctxa_active_sessions (session_id, created_at, expired, last_accessed_at, user_id, "
                + "username) values (?, ?, ?, ?, ?, ?)", id, at(lastAccess), expired, at(lastAccess), id, id);
    }

    private static void agent(String id, String status) {
        jdbc.update("insert into ctxa_agent_registration (agent_id, status, source, updated_at) values (?, ?, 'OBSERVED', "
                + "current_timestamp)", id, status);
    }

    private static void delegation(String id, Instant from, Instant to, Instant revokedAt) {
        jdbc.update("insert into ctxa_agent_delegation_record (delegation_id, delegator_id, agent_id, valid_from, "
                + "expires_at, revoked_at, recorded_by, recorded_at) values (?, 'person', 'agent', ?, ?, ?, 'admin', ?)",
                id, at(from), at(to), revokedAt == null ? null : at(revokedAt), at(from));
    }

    private static void confirmation(String id, String status, Instant expiresAt) {
        jdbc.update("insert into ctxa_agent_confirmation (confirmation_id, subject_kind, user_id, agent_id, subject_key, "
                + "recipient_id, request_hash, request_method, request_target, trigger_kind, status, created_at, "
                + "expires_at) values (?, 'DELEGATED_AGENT', 'person', 'agent', ?, 'person', ?, 'POST', '/api/x', "
                + "'POLICY', ?, ?, ?)", id, "person::" + id, id, status, at(expiresAt.minus(Duration.ofHours(1))),
                at(expiresAt));
    }

    /** A decision of a user as the decision service keeps it, with what the console reads of it. */
    private static void decision(String id, String user, String action, String attempt, Instant moment) {
        jdbc.update("insert into ctxa_ai_security_decision_observation (observation_id, user_id, final_action, "
                + "attempt_kind, created_at) values (?, ?, ?, ?, ?)", id, user, action, attempt, at(moment));
    }

    private static LocalDateTime local(Instant moment) {
        return LocalDateTime.ofInstant(moment, ZoneId.systemDefault());
    }

    private static void challenges(String user, Instant hour, long count) {
        jdbc.update("insert into ctxa_zt_item_hourly (bucket_start, dimension, item, detail, counted) "
                + "values (?, 'USER', ?, 'CHALLENGE', ?)", at(hour), user, count);
    }

    /** A decision record sealed after the one before it, written as the audit writes it; returns its hash. */
    private static String sealed(String resource, Instant moment, String previous, HmacEvidenceSigner signer) {
        AuditLog record = AuditLog.builder()
                .timestamp(LocalDateTime.ofInstant(moment, ZoneId.systemDefault()))
                .principalName("alice")
                .resourceIdentifier(resource)
                .eventCategory("SECURITY_DECISION")
                .action("DECIDE")
                .decision("ALLOW")
                .reason("as decided")
                .build();
        DecisionRecordSeal.seal(record, previous, signer);
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, event_category, action, "
                        + "decision, reason, record_hash, previous_record_hash, signature_key_id, record_signature) "
                        + "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Timestamp.valueOf(record.getTimestamp()),
                record.getPrincipalName(), record.getResourceIdentifier(), record.getEventCategory(), record.getAction(),
                record.getDecision(), record.getReason(), record.getRecordHash(), record.getPreviousRecordHash(),
                record.getSignatureKeyId(), record.getRecordSignature());
        return record.getRecordHash();
    }

    /** A clock the test moves on, as the passes of the hourly tables follow one another. */
    private static final class MovableClock extends Clock {

        private Instant now;

        private MovableClock(Instant now) {
            this.now = now;
        }

        void move(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.systemDefault();
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
