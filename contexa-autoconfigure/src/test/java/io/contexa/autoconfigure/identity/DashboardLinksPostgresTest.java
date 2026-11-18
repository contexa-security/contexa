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

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.admin.web.auth.service.UserListFilters;
import io.contexa.contexaiam.admin.web.auth.service.UserListFilters.Filter;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.dashboard.DashboardHourlyStats;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries;
import io.contexa.contexaiam.admin.web.dashboard.DashboardQueries.Accounts;
import io.contexa.contexaiam.admin.web.monitoring.controller.SecurityMonitorController;
import io.contexa.contexaiam.admin.web.monitoring.dto.DecisionRecordIntegrity;
import io.contexa.contexaiam.admin.web.monitoring.service.DecisionRecordSealCheck;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityEventQueries;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
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
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K92, K100 on a real PostgreSQL database: every link of the dashboard that opens a list opens the very records its
 * number counts. The broken seals the hourly pass counts are the records the security event log lists by its filter
 * (and its CSV holds), the users each number of the IAM card counts are the users the list of users filters, a user's
 * row opens that user and no other whose name holds it, and the policy list's filter reads the policies of the IDs.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class DashboardLinksPostgresTest {

    private static final HmacEvidenceSigner SIGNER = new HmacEvidenceSigner(Map.of("k1",
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8)), "k1");

    private static PostgresTestDatabase database;
    private static LocalContainerEntityManagerFactoryBean entityManagers;
    private static JdbcTemplate jdbc;
    private static RoleHierarchyImpl hierarchy;
    private static LastAdministratorGuard guard;
    private static UserRepository users;
    private static AuditLogRepository auditLog;
    private static PolicyRepository policies;

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS).plus(Duration.ofMinutes(30));
    private final Clock clock = Clock.fixed(now, ZoneId.systemDefault());
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
        entityManagers.setPersistenceUnitName("contexa-dashboard-links");
        entityManagers.setPackagesToScan("io.contexa.contexacommon.entity", "io.contexa.contexaiam.domain.entity");
        entityManagers.setJpaPropertyMap(Map.of(
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy",
                "hibernate.implicit_naming_strategy",
                "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        entityManagers.afterPropertiesSet();
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagers.getObject());
        JpaRepositoryFactory repositories = new JpaRepositoryFactory(entityManager);
        users = repositories.getRepository(UserRepository.class);
        RoleRepository roles = repositories.getRepository(RoleRepository.class);
        auditLog = repositories.getRepository(AuditLogRepository.class);
        policies = repositories.getRepository(PolicyRepository.class);
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
                + "ctxa_app_group, ctxa_audit_log, ctxa_dashboard_seal_hourly, ctxa_dashboard_seal_mismatch, ctxa_policy "
                + "restart identity cascade");
        hierarchy.setHierarchy("");
    }

    // ----- K92: the broken seals the dashboard counts are the records the security event log lists -----

    @Test
    @DisplayName("K92: the event log's seal filter lists the broken seals the dashboard counts, and its CSV holds them")
    void theSealFilterListsTheBrokenSealsCounted() throws Exception {
        Instant from = now.minus(Duration.ofDays(7));
        Instant hourOfFrom = from.truncatedTo(ChronoUnit.HOURS);
        // a record between the start of the period's first hour and the period's start, two inside, two intact
        String previous = sealed("on-the-boundary", hourOfFrom.plus(Duration.ofMinutes(10)), null);
        previous = sealed("intact-1", from.plus(Duration.ofHours(1)), previous);
        previous = sealed("inside-1", from.plus(Duration.ofHours(2)), previous);
        previous = sealed("intact-2", now.minus(Duration.ofHours(3)), previous);
        sealed("inside-2", now.minus(Duration.ofHours(2)), previous);
        jdbc.update("update ctxa_audit_log set reason = 'changed afterwards' where resource_identifier not like 'intact%'");
        stats().rebuildOnce();
        SecurityMonitorController monitor = monitor();
        Model model = new ExtendedModelMap();

        long counted = queries.sealMismatches(from, now);
        // the dashboard's link: the decision records the count counts, from the hour the count starts at
        monitor.monitor("SECURITY_DECISION", "SEAL_MISMATCH", null, null, 168, hourOfFrom.toString(), 0, model);
        Page<?> page = (Page<?>) model.getAttribute("logPage");
        DecisionRecordIntegrity integrity = (DecisionRecordIntegrity) model.getAttribute("integrity");

        assertThat(counted).isEqualTo(3);
        assertThat(page.getTotalElements()).isEqualTo(counted);
        assertThat(page.getContent()).map(AuditLog.class::cast).extracting(AuditLog::getResourceIdentifier)
                .containsExactly("inside-2", "inside-1", "on-the-boundary");
        assertThat(page.getContent()).map(AuditLog.class::cast)
                .allMatch(record -> "MISMATCH".equals(integrity.of(record.getId())));
        assertThat(jdbc.queryForObject("select count(*) from ctxa_dashboard_seal_mismatch", Long.class))
                .isEqualTo(counted);

        // K108: the CSV of the same filter holds the same records
        MockHttpServletResponse csv = new MockHttpServletResponse();
        monitor.exportCsv("SECURITY_DECISION", "SEAL_MISMATCH", 168, hourOfFrom.toString(), null, null, csv);
        assertThat(rows(csv)).hasSize(3).allMatch(row -> row.contains("SECURITY_DECISION"));
    }

    @Test
    @DisplayName("K92: a record whose seal matches again leaves the list when its hour is checked again; pages add up")
    void aSealThatMatchesAgainLeavesTheList() {
        Instant hour = now.minus(Duration.ofHours(5)).truncatedTo(ChronoUnit.HOURS);
        String previous = null;
        for (int i = 0; i < 5; i++) {
            previous = sealed("decision-" + i, hour.plus(Duration.ofMinutes(5L * (i + 1))), previous);
        }
        jdbc.update("update ctxa_audit_log set reason = 'changed afterwards'");
        stats().rebuildOnce();
        SecurityMonitorController monitor = monitor();
        Model first = new ExtendedModelMap();
        Model second = new ExtendedModelMap();

        monitor.monitor(null, "SEAL_MISMATCH", null, null, 24, null, 0, first);
        Page<?> all = (Page<?>) first.getAttribute("logPage");
        assertThat(all.getTotalElements()).isEqualTo(queries.sealMismatches(now.minus(Duration.ofHours(24)), now))
                .isEqualTo(5);

        jdbc.update("update ctxa_audit_log set reason = 'as decided'");
        // a pass after a start checks the last two days again
        stats().rebuildOnce();
        monitor.monitor(null, "SEAL_MISMATCH", null, null, 24, null, 0, second);

        assertThat(((Page<?>) second.getAttribute("logPage")).getTotalElements()).isZero();
        assertThat(queries.sealMismatches(now.minus(Duration.ofHours(24)), now)).isZero();
    }

    @Test
    @DisplayName("K92: an hour counted before its records were kept by ID is checked again by the first pass")
    void anHourCountedBeforeTheRecordsWereKeptIsCheckedAgain() {
        // An installed console: the hour of five days ago was counted with one broken seal, and nothing kept by ID.
        Instant hour = now.minus(Duration.ofDays(5)).truncatedTo(ChronoUnit.HOURS);
        sealed("old-decision", hour.plus(Duration.ofMinutes(20)), null);
        jdbc.update("update ctxa_audit_log set reason = 'changed afterwards'");
        jdbc.update("insert into ctxa_dashboard_seal_hourly (bucket_start, checked, mismatched, unverifiable, computed_at) "
                + "values (?, 1, 1, 0, ?)", Timestamp.from(hour), Timestamp.from(now));

        stats().rebuildOnce();

        assertThat(jdbc.queryForObject("select count(*) from ctxa_dashboard_seal_mismatch where bucket_start = ?",
                Long.class, Timestamp.from(hour))).isEqualTo(1);
        Model model = new ExtendedModelMap();
        monitor().monitor(null, "SEAL_MISMATCH", null, null, 168, null, 0, model);
        assertThat(((Page<?>) model.getAttribute("logPage")).getTotalElements())
                .isEqualTo(queries.sealMismatches(now.minus(Duration.ofDays(7)), now)).isEqualTo(1);
    }

    @Test
    @DisplayName("K92: the records kept by ID go with the seal counts when the aggregates' retention ends")
    void theRecordsKeptByIdGoWithTheSealCounts() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        Instant old = now.minus(Duration.ofDays(properties.getConsole().getAggregateRetentionDays() + 2L))
                .truncatedTo(ChronoUnit.HOURS);
        // two records the audit log keeps: the older one's row goes with its hour's counts, the recent one's stays
        sealed("old", old.plus(Duration.ofMinutes(5)), null);
        sealed("recent", now.minus(Duration.ofHours(2)), null);
        long oldId = jdbc.queryForObject("select id from ctxa_audit_log where resource_identifier = 'old'", Long.class);
        long recentId = jdbc.queryForObject("select id from ctxa_audit_log where resource_identifier = 'recent'", Long.class);
        jdbc.update("insert into ctxa_dashboard_seal_mismatch (audit_id, bucket_start, computed_at) values (?, ?, ?), "
                + "(?, ?, ?)", oldId, Timestamp.from(old), Timestamp.from(now), recentId,
                Timestamp.from(now.minus(Duration.ofHours(2))), Timestamp.from(now));

        new DashboardHourlyStats(() -> jdbc, auditLog, null, properties, clock).purgeOnce();

        assertThat(jdbc.queryForList("select audit_id from ctxa_dashboard_seal_mismatch", Long.class))
                .containsExactly(recentId);
    }

    @Test
    @DisplayName("K141: a broken seal the audit retention deleted leaves the count and the list alike, and its row goes")
    void aBrokenSealTheRetentionDeletedLeavesBoth() {
        Instant hour = now.minus(Duration.ofHours(6)).truncatedTo(ChronoUnit.HOURS);
        String previous = sealed("kept", hour.plus(Duration.ofMinutes(10)), null);
        sealed("deleted", hour.plus(Duration.ofMinutes(20)), previous);
        jdbc.update("update ctxa_audit_log set reason = 'changed afterwards'");
        stats().rebuildOnce();
        assertThat(queries.sealMismatches(now.minus(Duration.ofDays(1)), now)).isEqualTo(2);

        // the audit retention deletes one of them
        jdbc.update("delete from ctxa_audit_log where resource_identifier = 'deleted'");
        Model model = new ExtendedModelMap();
        monitor().monitor(null, "SEAL_MISMATCH", null, null, 24, null, 0, model);

        assertThat(queries.sealMismatches(now.minus(Duration.ofDays(1)), now)).isEqualTo(1)
                .isEqualTo(((Page<?>) model.getAttribute("logPage")).getTotalElements());
        new DashboardHourlyStats(() -> jdbc, auditLog, null, new SecurityZeroTrustProperties(), clock).purgeOnce();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_dashboard_seal_mismatch", Long.class)).isEqualTo(1);
    }

    // ----- K138: every filter of the security event log in one statement, the user name and the subject kind with it -----

    @Test
    @DisplayName("K138: each filter lists what the repository's reads listed, and the name and the subject narrow it")
    void eachFilterListsWhatItListedAndTheNameNarrowsIt() {
        LocalDateTime since = local(now.minus(Duration.ofDays(3)));
        LocalDateTime until = local(now);
        String[] categories = {"SECURITY_DECISION", "AUTHENTICATION_FAILURE", "ADMIN_OVERRIDE", "USER_BLOCKED"};
        String[] decisions = {"ALLOW", "BLOCK", "CHALLENGE", "ESCALATE", "DENY"};
        for (int i = 0; i < 60; i++) {
            event(categories[i % 4], i % 3 == 0 ? "bob" : "alice", decisions[i % 5], i % 7 == 0 ? "REFUSED" : "DONE",
                    i % 2 == 0 ? "10.0.0." + (i % 5) : null, i % 4 * 0.2, i % 6 == 0 ? "DELEGATED_AGENT" : "HUMAN_USER",
                    now.minus(Duration.ofHours(i * 2L + 1)));
        }
        event("SECURITY_DECISION", "bob", "ALLOW", "DONE", null, 0.1, "HUMAN_USER", now.minus(Duration.ofDays(5)));
        SecurityEventQueries events = new SecurityEventQueries(() -> jdbc);
        PageRequest all = PageRequest.of(0, 500);
        PageRequest sorted = PageRequest.of(0, 500, Sort.by(Sort.Direction.DESC, "timestamp"));
        Map<String, List<Long>> before = new LinkedHashMap<>();
        before.put("AFTER_HOURS", ids(auditLog.findAfterHoursAccess(since, all)));
        before.put("DISTINCT_IP", ids(auditLog.findByTimestampAfterAndClientIpNotNull(since, sorted)));
        before.put("HIGH_RISK", ids(auditLog.findByTimestampAfterAndRiskScoreGte(since, 0.4, sorted)));
        before.put("DECISION_ALLOW", ids(auditLog.findByTimestampAfterAndDecision(since, "ALLOW", sorted)));
        before.put("DECISION_DENY", ids(auditLog.findByTimestampAfterAndDecision(since, "DENY", sorted)));
        for (String decision : List.of("ALLOW", "BLOCK", "CHALLENGE", "ESCALATE")) {
            before.put("ZT_" + decision, ids(auditLog.findByCategoryAndDecision("SECURITY_DECISION", decision, since,
                    sorted)));
        }
        before.put("ADMIN_OVERRIDE_APPLIED", ids(auditLog.findAdminOverridesBetween(since, until, sorted)));
        before.put("USER_BLOCKED", ids(auditLog.findByTimestampAfterAndCategory(since, "USER_BLOCKED", sorted)));

        for (Map.Entry<String, List<Long>> filter : before.entrySet()) {
            List<Long> listed = events.ids(new SecurityEventQueries.Criteria(since, until, null, filter.getKey(), null,
                    null), all).getContent();
            assertThat(listed).as(filter.getKey()).containsExactlyInAnyOrderElementsOf(filter.getValue()).isNotEmpty();
            // the user name and the subject kind narrow it: the records of both, and only those
            List<Long> narrowed = events.ids(new SecurityEventQueries.Criteria(since, until, null, filter.getKey(), "BO",
                    "HUMAN_USER"), all).getContent();
            List<Long> expected = listed.stream().filter(DashboardLinksPostgresTest::bobAsAPerson).toList();
            assertThat(narrowed).as(filter.getKey() + " narrowed").containsExactlyInAnyOrderElementsOf(expected);
        }
        // a category, a user name and a subject kind with no filter, as the repository's reads listed them
        assertThat(events.ids(new SecurityEventQueries.Criteria(since, until, "AUTHENTICATION_FAILURE", null, "bob", null),
                all).getContent()).containsExactlyElementsOf(ids(auditLog.findByTimestampAfterAndCategoryAndPrincipalNameLike(
                since, "AUTHENTICATION_FAILURE", "%bob%", sorted)));
        assertThat(events.ids(new SecurityEventQueries.Criteria(since, until, null, null, null, "DELEGATED_AGENT"), all)
                .getContent()).containsExactlyInAnyOrderElementsOf(ids(auditLog.findByTimestampAfterAndSubjectKind(since,
                "DELEGATED_AGENT", sorted)));
        // the addresses of the records, the user name applied
        Page<Object[]> addresses = events.addresses(new SecurityEventQueries.Criteria(since, until, null, "DISTINCT_IP",
                "bob", null), PageRequest.of(0, 20));
        Map<String, Long> bobs = new LinkedHashMap<>();
        jdbc.query("select client_ip, count(*) from ctxa_audit_log where timestamp >= ? and client_ip is not null "
                + "and principal_name = 'bob' group by client_ip", (ResultSet rs) -> {
                    bobs.put(rs.getString(1), rs.getLong(2));
                }, Timestamp.valueOf(since));
        assertThat(addresses.getTotalElements()).isEqualTo(bobs.size());
        assertThat(addresses.getContent()).allMatch(row -> bobs.get((String) row[0]).equals(row[1]));
        assertThat(addresses.getContent().stream().mapToLong(row -> (Long) row[1]).sum())
                .isLessThan(auditLog.findByTimestampAfterAndClientIpNotNull(since, all).getTotalElements());
    }

    // ----- K92: the users each number of the IAM card counts are the users the list of users filters -----

    @Test
    @DisplayName("K92: every filter of the list of users holds the users the dashboard's number counts, page by page")
    void everyFilterHoldsTheUsersTheNumberCounts() {
        long admin = role("ROLE_ADMIN");
        long ops = group("ops", admin);
        long directAdmin = user("direct.admin", false);
        userRole(directAdmin, admin);
        long groupAdmin = user("group.admin", true);
        userGroup(groupAdmin, ops);
        long locked = user("locked.now", true);
        jdbc.update("update ctxa_users set account_locked = true, lock_expires_at = ? where id = ?",
                at(now.plus(Duration.ofMinutes(10))), locked);
        long lockEnded = user("lock.ended", true);
        jdbc.update("update ctxa_users set account_locked = true, lock_expires_at = ? where id = ?",
                at(now.minus(Duration.ofMinutes(10))), lockEnded);
        long dormant = user("dormant.login", true);
        jdbc.update("update ctxa_users set last_login_at = ? where id = ?", at(now.minus(Duration.ofDays(100))), dormant);
        long neverSigned = user("never.signed", true);
        jdbc.update("update ctxa_users set created_at = ? where id = ?", at(now.minus(Duration.ofDays(120))), neverSigned);
        long noAddress = user("no.address", true);
        jdbc.update("update ctxa_users set email = 'no-address' where id = ?", noAddress);
        long synthetic = user("synthetic", true);
        jdbc.update("update ctxa_users set email = 'synthetic@bridge.invalid' where id = ?", synthetic);
        // Not accounts of people: a disabled one, a bridge copy, an agent's (each locked, dormant and an administrator
        // too). The administrator rule counts an agent's account that holds the role, as the dashboard does.
        List<Long> others = new ArrayList<>();
        for (String name : List.of("disabled", "bridged", "report-bot")) {
            long other = user(name, false);
            others.add(other);
            jdbc.update("update ctxa_users set account_locked = true, lock_expires_at = ?, last_login_at = ? where id = ?",
                    at(now.plus(Duration.ofMinutes(10))), at(now.minus(Duration.ofDays(100))), other);
            userRole(other, admin);
        }
        jdbc.update("update ctxa_users set enabled = false where username = 'disabled'");
        jdbc.update("update ctxa_users set bridge_managed = true where username = 'bridged'");
        jdbc.update("update ctxa_users set email = 'report-bot@agents.invalid' where username = 'report-bot'");
        VerificationCoverageService coverage = new VerificationCoverageService(users, "bridge.invalid", () -> true,
                () -> false);
        UserListFilters filters = new UserListFilters(() -> jdbc, users, guard, coverage, clock);
        Accounts accounts = queries.accounts(now, now.minus(Duration.ofDays(90)), null);

        assertThat(all(filters, Filter.ADMIN)).hasSize((int) guard.administratorCount())
                .containsExactly(directAdmin, groupAdmin, others.get(2));
        assertThat(all(filters, Filter.ADMIN_NO_MFA)).hasSize((int) guard.administratorsWithoutMfaCount())
                .containsExactly(directAdmin, others.get(2));
        assertThat(all(filters, Filter.LOCKED)).hasSize((int) accounts.locked()).containsExactly(locked);
        assertThat(all(filters, Filter.DORMANT)).hasSize((int) accounts.dormant())
                .containsExactlyInAnyOrder(dormant, neverSigned);
        // without passkeys every account counts whose address reaches nobody (the disabled one aside)
        assertThat(all(filters, Filter.NO_FACTOR)).hasSize((int) coverage.usersWithoutFactor())
                .containsExactlyInAnyOrder(noAddress, synthetic);
        assertThat(filters.ids(Filter.DORMANT, 0, 1).getTotalElements()).isEqualTo(accounts.dormant());
    }

    @Test
    @DisplayName("K100: a user's row opens that user only, the case aside, never another user whose name holds it")
    void aUsersRowOpensThatUserOnly() {
        long alice = user("alice", false);
        user("alice2", false);
        user("malice", false);
        long bridged = user("5f1c-hash", false);
        jdbc.update("update ctxa_users set bridge_managed = true, external_subject_id = 'bob@app.example' where id = ?",
                bridged);
        user("bob@app.example.org", false);
        UserListFilters filters = new UserListFilters(() -> jdbc, users, guard, null, clock);

        assertThat(filters.named("alice", 0, 15).getContent()).containsExactly(alice);
        assertThat(filters.named(" ALICE ", 0, 15).getContent()).containsExactly(alice);
        assertThat(filters.named("ali", 0, 15).getContent()).isEmpty();
        assertThat(filters.named("bob@app.example", 0, 15).getContent()).containsExactly(bridged);
        // the list of the word still finds every user whose name holds it
        assertThat(users.findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase("alice", "alice",
                PageRequest.of(0, 15)).getTotalElements()).isEqualTo(3);
    }

    // ----- K92: the policy list's filter reads the policies of the IDs, with its other filters -----

    @Test
    @DisplayName("K92: the policy list's filter lists the policies of the IDs only, its other filters applied")
    void thePolicyFilterListsThePoliciesOfTheIds() {
        long first = policy("first", "PENDING", true);
        long second = policy("second", "APPROVED", true);
        long third = policy("third", "PENDING", false);
        policy("fourth", "PENDING", true);

        assertThat(policies.searchByFiltersAmong(null, null, null, Set.of(first, second, third),
                PageRequest.of(0, 10)).getContent()).extracting(Policy::getId)
                .containsExactlyInAnyOrder(first, second, third);
        assertThat(policies.searchByFiltersAmong(null, Policy.ApprovalStatus.PENDING, true, Set.of(first, second, third),
                PageRequest.of(0, 10)).getContent()).extracting(Policy::getId).containsExactly(first);
        assertThat(policies.searchByFiltersAmong(null, null, null, Set.of(), PageRequest.of(0, 10)).getTotalElements())
                .isZero();
    }

    // ----- helpers -----

    /** Whether the record is of the name bob and of a person. */
    private static boolean bobAsAPerson(Long id) {
        return Boolean.TRUE.equals(jdbc.queryForObject("select principal_name = 'bob' and subject_kind = 'HUMAN_USER' "
                + "from ctxa_audit_log where id = ?", Boolean.class, id));
    }

    private static List<Long> ids(Page<AuditLog> page) {
        return page.getContent().stream().map(AuditLog::getId).toList();
    }

    private static LocalDateTime local(Instant moment) {
        return LocalDateTime.ofInstant(moment, ZoneId.systemDefault());
    }

    private static void event(String category, String principal, String decision, String outcome, String address,
                              double risk, String subjectKind, Instant moment) {
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, decision, outcome, "
                + "event_category, client_ip, risk_score, subject_kind) values (?, ?, '/api/x', ?, ?, ?, ?, ?, ?)",
                Timestamp.from(moment), principal, decision, outcome, category, address, risk, subjectKind);
    }

    private DashboardHourlyStats stats() {
        return new DashboardHourlyStats(() -> jdbc, auditLog, new DecisionRecordSealCheck(auditLog, () -> SIGNER), null,
                clock);
    }

    private SecurityMonitorController monitor() {
        SecurityMonitorController monitor = new SecurityMonitorController(auditLog, new CsvExportService());
        monitor.setEvidenceSigner(SIGNER);
        monitor.setEventQueries(new SecurityEventQueries(() -> jdbc));
        return monitor;
    }

    /** The data rows of a CSV, the header left out. */
    private static List<String> rows(MockHttpServletResponse csv) throws Exception {
        List<String> lines = new ArrayList<>(List.of(csv.getContentAsString(StandardCharsets.UTF_8).split("\r?\n")));
        lines.removeIf(String::isBlank);
        return lines.subList(1, lines.size());
    }

    /** Every ID of a filter, read a page of one at a time. */
    private static List<Long> all(UserListFilters filters, Filter filter) {
        List<Long> ids = new ArrayList<>();
        for (int page = 0; ; page++) {
            Page<Long> found = filters.ids(filter, page, 1);
            ids.addAll(found.getContent());
            if (!found.hasNext()) {
                return ids;
            }
        }
    }

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

    private static long policy(String name, String approval, boolean active) {
        return jdbc.queryForObject("insert into ctxa_policy (name, effect, priority, approval_status, source, is_active) "
                + "values (?, 'ALLOW', 1, ?, 'MANUAL', ?) returning id", Long.class, name, approval, active);
    }

    private static Timestamp at(Instant moment) {
        return Timestamp.from(moment);
    }

    /** A decision record sealed after the one before it, written as the audit writes it; returns its hash. */
    private static String sealed(String resource, Instant moment, String previous) {
        AuditLog record = AuditLog.builder()
                .timestamp(LocalDateTime.ofInstant(moment, ZoneId.systemDefault()))
                .principalName("alice")
                .resourceIdentifier(resource)
                .eventCategory("SECURITY_DECISION")
                .action("DECIDE")
                .decision("ALLOW")
                .reason("as decided")
                .build();
        DecisionRecordSeal.seal(record, previous, SIGNER);
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, event_category, action, "
                        + "decision, reason, record_hash, previous_record_hash, signature_key_id, record_signature) "
                        + "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", Timestamp.valueOf(record.getTimestamp()),
                record.getPrincipalName(), record.getResourceIdentifier(), record.getEventCategory(), record.getAction(),
                record.getDecision(), record.getReason(), record.getRecordHash(), record.getPreviousRecordHash(),
                record.getSignatureKeyId(), record.getRecordSignature());
        return record.getRecordHash();
    }
}
