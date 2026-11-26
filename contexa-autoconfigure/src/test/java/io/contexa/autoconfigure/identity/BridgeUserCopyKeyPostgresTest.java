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
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.sync.UserCopyMergeContributor;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The copy of an application's user on the database customers run: one row per person whichever way the bridge read
 * them, and a row a synchronisation made before, under a key that named the way, is the person's row from then on, keeping
 * its id and its name. A sign-in time read ahead of the clock is not the copy's last sign-in.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class BridgeUserCopyKeyPostgresTest {

    private final RefusingContributor contributor = new RefusingContributor();
    private PostgresTestDatabase database;
    private LocalContainerEntityManagerFactoryBean entityManagers;
    private TransactionTemplate transactions;
    private DefaultBridgeUserMirrorSyncService sync;
    private UserRepository users;
    private JdbcTemplate jdbc;

    @BeforeEach
    void installAndStart() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa");
        entityManagers.setPackagesToScan("io.contexa.contexacommon.entity");
        entityManagers.setJpaPropertyMap(Map.of(
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy",
                "hibernate.implicit_naming_strategy",
                "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        entityManagers.afterPropertiesSet();
        transactions = new TransactionTemplate(new JpaTransactionManager(entityManagers.getObject()));
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagers.getObject());
        JpaRepositoryFactory repositories = new JpaRepositoryFactory(entityManager);
        users = repositories.getRepository(UserRepository.class);
        sync = new DefaultBridgeUserMirrorSyncService(users,
                repositories.getRepository(BridgeUserProfileRepository.class), new BridgeProperties(), new ObjectMapper(),
                null);
        sync.setRolePermissions(repositories.getRepository(UserRolePermissionRepository.class));
        sync.setMergeContributors(List.of(contributor));
    }

    @AfterEach
    void close() {
        SecurityContextHolder.clearContext();
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    @Test
    @DisplayName("새 사람은 보안 문맥, 직접 전달, 세션 어느 길로 읽혀도 행이 하나다")
    void aNewPersonIsOneRowWhicheverWayReadThem() {
        read("alice", "SECURITY_CONTEXT");
        read("alice", "EXPLICIT_HANDOFF");
        read("alice", "SESSION");

        assertThat(rowsOf("alice")).isEqualTo(1);
        assertThat(jdbc.queryForObject("select bridge_subject_key from ctxa_users where external_subject_id = 'alice'",
                String.class)).isEqualTo(newKey("alice"));
    }

    @Test
    @DisplayName("옛 키로 저장된 행은 다른 길로 읽혀도 그 행이 되고 id와 사용자 이름을 그대로 둔다")
    void aRowUnderTheOldKeyStaysThePersonsRow() {
        long kept = oldRow("alice", "SECURITY_CONTEXT");

        read("alice", "EXPLICIT_HANDOFF");
        read("alice", "SESSION");

        assertThat(rowsOf("alice")).isEqualTo(1);
        Map<String, Object> row = jdbc.queryForMap("select id, username, bridge_subject_key, authentication_source "
                + "from ctxa_users where external_subject_id = 'alice'");
        assertThat(((Number) row.get("id")).longValue()).isEqualTo(kept);
        assertThat(row.get("username")).isEqualTo(oldKey("SECURITY_CONTEXT", "alice"));
        assertThat(row.get("bridge_subject_key")).isEqualTo(newKey("alice"));
        assertThat(row.get("authentication_source")).isEqualTo("SESSION");
    }

    /**
     * bridge v2 B5-3 (decision Q3): this test kept the other rows as they were until a merge existed; the synchronisation
     * that moves the oldest row to the new key now merges the others into it.
     */
    @Test
    @DisplayName("이미 길마다 갈라진 행은 가장 먼저 만든 행으로 합쳐 한 행이 된다")
    void rowsAlreadySplitAreMergedIntoTheOldest() {
        long first = oldRow("alice", "SECURITY_CONTEXT");
        long second = oldRow("alice", "EXPLICIT_HANDOFF");

        read("alice", "SESSION");
        read("alice", "EXPLICIT_HANDOFF");

        assertThat(rowsOf("alice")).isEqualTo(1);
        assertThat(jdbc.queryForObject("select id from ctxa_users where external_subject_id = 'alice'", Long.class))
                .isEqualTo(first);
        assertThat(jdbc.queryForObject("select bridge_subject_key from ctxa_users where id = ?", String.class, first))
                .isEqualTo(newKey("alice"));
        assertThat(jdbc.queryForObject("select count(*) from ctxa_users where id = ?", Integer.class, second)).isZero();
    }

    @Test
    @DisplayName("합친 행의 그룹·역할·권한은 남는 행으로 옮겨지고 겹치는 것은 하나만 남으며, 프로필은 사라지고, 관리자가 끈 쪽을 따른다")
    void aMergedRowsGroupsRolesAndGrantsBecomeTheKeptRowsAndItsOffStateStays() {
        long first = oldRow("alice", "SECURITY_CONTEXT");
        long second = oldRow("alice", "EXPLICIT_HANDOFF");
        long sales = jdbc.queryForObject("insert into ctxa_app_group (group_name) values ('sales') returning group_id",
                Long.class);
        long audit = jdbc.queryForObject("insert into ctxa_app_group (group_name) values ('audit') returning group_id",
                Long.class);
        long reader = jdbc.queryForObject("insert into ctxa_role (role_name) values ('ROLE_READER') returning role_id",
                Long.class);
        long export = jdbc.queryForObject(
                "insert into ctxa_permission (permission_name) values ('ORDERS_EXPORT') returning permission_id", Long.class);
        jdbc.update("insert into ctxa_user_groups (user_id, group_id) values (?, ?), (?, ?), (?, ?)",
                first, sales, second, sales, second, audit);
        jdbc.update("insert into ctxa_user_roles (role_id, user_id, assigned_at) values (?, ?, current_timestamp)",
                reader, second);
        jdbc.update("insert into ctxa_user_role_permissions (user_id, role_id, permission_id, assigned_at) "
                + "values (?, ?, ?, current_timestamp)", second, reader, export);
        jdbc.update("insert into ctxa_bridge_user_profile (user_id, created_at) values (?, current_timestamp)", second);
        jdbc.update("update ctxa_users set enabled = false where id = ?", second);

        read("alice", "SESSION");

        assertThat(rowsOf("alice")).isEqualTo(1);
        assertThat(jdbc.queryForList("select group_id from ctxa_user_groups where user_id = ? order by group_id",
                Long.class, first)).containsExactly(sales, audit);
        assertThat(jdbc.queryForList("select role_id from ctxa_user_roles where user_id = ?", Long.class, first))
                .containsExactly(reader);
        assertThat(jdbc.queryForList("select permission_id from ctxa_user_role_permissions where user_id = ?", Long.class,
                first)).containsExactly(export);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_bridge_user_profile where user_id = ?", Integer.class,
                second)).isZero();
        assertThat(jdbc.queryForObject("select enabled from ctxa_users where id = ?", Boolean.class, first)).isFalse();
    }

    @Test
    @DisplayName("합치기를 거부한 행은 남고 남는 행도 옛 키를 지켜, 거부 사유가 풀린 다음 동기화가 합친다")
    void aRefusedMergeKeepsBothRowsAndTheOldKeyUntilALaterSynchronisationMerges() {
        long first = oldRow("alice", "SECURITY_CONTEXT");
        oldRow("alice", "EXPLICIT_HANDOFF");
        contributor.refusing = true;

        read("alice", "SESSION");

        assertThat(rowsOf("alice")).isEqualTo(2);
        assertThat(jdbc.queryForObject("select bridge_subject_key from ctxa_users where id = ?", String.class, first))
                .isEqualTo(oldKey("SECURITY_CONTEXT", "alice"));
        List<UserRepository.SplitCopies> apart = users.findSplitCopies(PageRequest.of(0, 51));
        assertThat(apart).extracting(UserRepository.SplitCopies::getSubject).containsExactly("alice");
        assertThat(apart).extracting(UserRepository.SplitCopies::getCopies).containsExactly(2L);

        contributor.refusing = false;
        read("alice", "SESSION");

        assertThat(rowsOf("alice")).isEqualTo(1);
        assertThat(users.findSplitCopies(PageRequest.of(0, 51))).isEmpty();
        assertThat(jdbc.queryForObject("select bridge_subject_key from ctxa_users where id = ?", String.class, first))
                .isEqualTo(newKey("alice"));
        assertThat(contributor.merged).containsExactly(oldKey("SECURITY_CONTEXT", "alice") + " <- "
                + oldKey("EXPLICIT_HANDOFF", "alice"));
    }

    @Test
    @DisplayName("미래로 읽힌 레거시 로그인 시각은 사본의 마지막 로그인 시각이 되지 않고, 레거시 속성 전체는 저장하지 않는다")
    void aSignInTimeReadAheadOfTheClockIsNotTheCopysLastSignIn() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_USER"));
        authentication.setDetails(Map.of("loginTime", "20261125103000"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        BridgeProperties properties = new BridgeProperties();
        RequestContextSnapshot context = new RequestContextSnapshot("/orders", "GET", "198.51.100.9", "ua", "s-1", "r-1",
                "/orders", null, false, Instant.now());
        AuthenticationStamp stamp = new SecurityContextAuthenticationStampResolver()
                .resolve(request, context, properties).orElseThrow();

        transactions.executeWithoutResult(status -> sync.sync(stamp, null, context));

        Map<String, Object> row = jdbc.queryForMap("select u.last_login_at, p.last_attributes_json from ctxa_users u "
                + "join ctxa_bridge_user_profile p on p.user_id = u.id where u.external_subject_id = 'alice'");
        assertThat(((Timestamp) row.get("last_login_at")).toInstant()).isBefore(Instant.parse("2100-01-01T00:00:00Z"));
        assertThat(row.get("last_attributes_json")).isNull();
    }

    private void read(String subject, String way) {
        transactions.executeWithoutResult(status -> sync.sync(new AuthenticationStamp(subject, subject, "USER", true,
                        "FORM", way, null, null, Instant.parse("2026-11-25T01:00:00Z"), "s-1", List.of("ROLE_USER"),
                        Map.of()),
                null, new RequestContextSnapshot("/orders", "GET", "198.51.100.9", "ua", "s-1", "r-1", "/orders", null,
                        false, Instant.now())));
    }

    /** A row a synchronisation made under the key that named the way, the day before. */
    private long oldRow(String subject, String way) {
        String key = oldKey(way, subject);
        jdbc.update("insert into ctxa_users (username, email, password, name, bridge_managed, external_auth_only, "
                + "external_subject_id, authentication_source, bridge_subject_key, last_bridged_at) values (?, ?, 'x', ?, "
                + "true, true, ?, ?, ?, current_timestamp - interval '1 day')",
                key, key + "@shadow.contexa.local", subject, subject, way, key);
        return jdbc.queryForObject("select id from ctxa_users where bridge_subject_key = ?", Long.class, key);
    }

    private int rowsOf(String subject) {
        return jdbc.queryForObject("select count(*) from ctxa_users where external_subject_id = ?", Integer.class, subject);
    }

    private static String oldKey(String way, String subject) {
        return "brg_" + sha256(way + "|GLOBAL|" + subject);
    }

    private static String newKey(String subject) {
        return "brg_" + sha256("SUBJECT|GLOBAL|" + subject);
    }

    /** A module keeping a state under a copy's name: it refuses while told to, and records what it merged. */
    private static final class RefusingContributor implements UserCopyMergeContributor {

        private volatile boolean refusing;
        private final List<String> merged = new CopyOnWriteArrayList<>();

        @Override
        public String refusal(String keptUsername, String mergedUsername) {
            return refusing ? "both copies hold passkeys" : null;
        }

        @Override
        public void merge(String keptUsername, String mergedUsername) {
            merged.add(keptUsername + " <- " + mergedUsername);
        }
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
