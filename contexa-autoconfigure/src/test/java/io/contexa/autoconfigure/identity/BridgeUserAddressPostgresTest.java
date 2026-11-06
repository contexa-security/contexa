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
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The address waiting for its user is kept on the database customers run: a new database has the column from the
 * schema, and a database installed before it gains it in place, with its rows, at the next start.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class BridgeUserAddressPostgresTest {

    private PostgresTestDatabase database;
    private LocalContainerEntityManagerFactoryBean entityManagers;
    private TransactionTemplate transactions;
    private DefaultBridgeUserMirrorSyncService sync;
    private JdbcTemplate jdbc;

    @AfterEach
    void close() {
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    private void installed() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
    }

    /** Contexa's persistence unit as CoreDataAutoConfiguration builds it, over the entities of the user copy. */
    private void started() {
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
        sync = new DefaultBridgeUserMirrorSyncService(repositories.getRepository(UserRepository.class),
                repositories.getRepository(BridgeUserProfileRepository.class), new BridgeProperties(), new ObjectMapper(),
                null);
    }

    private void shows(String email) {
        transactions.executeWithoutResult(status -> sync.sync(new AuthenticationStamp("alice", "Alice", "USER", true,
                        "FORM", "SECURITY_CONTEXT", null, null, null, "s-1", List.of("ROLE_USER"), Map.of("email", email)),
                null, new RequestContextSnapshot("/profile", "POST", "198.51.100.9", "ua", "s-1", "r-1", "/profile", null,
                        false, Instant.now())));
    }

    private Long copyId() {
        return jdbc.queryForObject("select id from ctxa_users where external_subject_id = 'alice'", Long.class);
    }

    private String address() {
        return jdbc.queryForObject("select email from ctxa_users where external_subject_id = 'alice'", String.class);
    }

    private String waiting() {
        return jdbc.queryForObject("select p.pending_email from ctxa_bridge_user_profile p join ctxa_users u "
                + "on u.id = p.user_id where u.external_subject_id = 'alice'", String.class);
    }

    private boolean confirmed(String address) {
        Long id = copyId();
        return Boolean.TRUE.equals(transactions.execute(status -> sync.confirmPendingEmail(id, address)));
    }

    private String told() {
        Long id = copyId();
        return transactions.execute(status -> sync.pendingEmail(id));
    }

    private int pendingColumns() {
        return jdbc.queryForObject("select count(*) from information_schema.columns where table_name = "
                + "'ctxa_bridge_user_profile' and column_name = 'pending_email'", Integer.class);
    }

    @Test
    @DisplayName("a new database keeps the address waiting until the user's proof moves the copy to it")
    void aNewDatabase() throws Exception {
        installed();
        assertThat(pendingColumns()).isEqualTo(1);
        started();

        shows("alice@corp.example");
        shows("thief@evil.example");

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("thief@evil.example");

        shows("alice@home.example");
        assertThat(told()).isEqualTo("alice@home.example");
        assertThat(confirmed("thief@evil.example")).isFalse();
        assertThat(confirmed("alice@home.example")).isTrue();

        assertThat(address()).isEqualTo("alice@home.example");
        assertThat(waiting()).isNull();
        assertThat(told()).isNull();
        assertThat(confirmed("alice@home.example")).isFalse();
    }

    @Test
    @DisplayName("a database installed before the column gains it at the next start, and its copies keep their rows")
    void aDatabaseInstalledBefore() throws Exception {
        installed();
        jdbc.execute("alter table ctxa_bridge_user_profile drop column pending_email");
        jdbc.update("insert into ctxa_users (username, email, password, name, bridge_managed, external_auth_only, "
                + "external_subject_id, authentication_source, bridge_subject_key) values ('brg_bob', "
                + "'bob@corp.example', 'x', 'Bob', true, true, 'bob', 'SECURITY_CONTEXT', 'brg_bob')");
        jdbc.update("insert into ctxa_bridge_user_profile (user_id, created_at, last_sync_hash) select id, "
                + "current_timestamp, 'h' from ctxa_users where username = 'brg_bob'");
        assertThat(pendingColumns()).isZero();

        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(database.dataSource(),
                new OssSchemaMaintenanceBacklog(database.dataSource()), false);

        assertThat(pendingColumns()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_bridge_user_profile p join ctxa_users u "
                + "on u.id = p.user_id where u.username = 'brg_bob' and p.last_sync_hash = 'h' "
                + "and p.pending_email is null", Integer.class)).isEqualTo(1);

        started();
        shows("alice@corp.example");
        shows("alice@home.example");
        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("alice@home.example");
        assertThat(confirmed("alice@home.example")).isTrue();
        assertThat(address()).isEqualTo("alice@home.example");
    }
}
