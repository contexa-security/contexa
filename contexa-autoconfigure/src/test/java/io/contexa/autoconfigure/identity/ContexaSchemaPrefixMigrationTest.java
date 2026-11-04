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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An existing Contexa database (the schema as it was before the ctxa_ prefix) is moved to the new names with its data,
 * its sequences and its recorded ownership, and then looks like a fresh installation; a database of an application that
 * only happens to have tables with the old names is never touched.
 * <p>
 * Runs on a PostgreSQL with pgvector whose URL is in CONTEXA_TEST_UPGRADE_DB_URL (user and password in
 * CONTEXA_TEST_DB_USERNAME and CONTEXA_TEST_DB_PASSWORD); every test works in schemas of its own that it drops again.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_UPGRADE_DB_URL", matches = ".+")
class ContexaSchemaPrefixMigrationTest {

    private static final String LEGACY = "ctxa_t_legacy";
    private static final String FRESH = "ctxa_t_fresh";
    private static final String HOST = "ctxa_t_host";

    private JdbcTemplate admin;

    @BeforeEach
    void schemas() {
        admin = new JdbcTemplate(inSchema("public"));
        admin.execute("create extension if not exists vector");
        for (String schema : List.of(LEGACY, FRESH, HOST)) {
            admin.execute("drop schema if exists " + schema + " cascade");
            admin.execute("create schema " + schema);
        }
    }

    @AfterEach
    void dropSchemas() {
        for (String schema : List.of(LEGACY, FRESH, HOST)) {
            admin.execute("drop schema if exists " + schema + " cascade");
        }
    }

    private static DataSource inSchema(String schema) {
        String url = System.getenv("CONTEXA_TEST_UPGRADE_DB_URL");
        url += (url.contains("?") ? "&" : "?") + "currentSchema=" + schema + ",public";
        return new DriverManagerDataSource(url, System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
    }

    private static void install(DataSource dataSource, String resource) throws Exception {
        String sql = new ClassPathResource(resource).getContentAsString(StandardCharsets.UTF_8);
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, resource,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(sql));
    }

    private static void legacyInstallation(DataSource dataSource) throws Exception {
        install(dataSource, "db/schema-before-ctxa-prefix.sql");
    }

    @Test
    void aLegacyInstallationMovesToTheNewNamesAndLooksLikeAFreshOne() throws Exception {
        DataSource legacy = inSchema(LEGACY);
        legacyInstallation(legacy);
        JdbcTemplate jdbc = new JdbcTemplate(legacy);
        jdbc.update("insert into users (username, email, password, name) values ('alice', 'alice@x.test', 'p', 'Alice')");
        jdbc.update("insert into users (username, email, password, name) values ('bob', 'bob@x.test', 'p', 'Bob')");
        jdbc.update("insert into contexa_schema_provenance (product_owner, schema_version, inventory_checksum) "
                + "values ('OSS', 'v-old', 'c'), ('HOST', 'v-old', 'c')");
        jdbc.update("insert into contexa_schema_inventory_object (product_owner, inventory_version, object_type, object_name) "
                + "values ('OSS', 'v-old', 'TABLE', 'users'), ('HOST', 'v-old', 'TABLE', 'orders')");

        ContexaSchemaPrefixMigration.Outcome outcome = new ContexaSchemaPrefixMigration(legacy).migrate();

        assertThat(outcome).isEqualTo(ContexaSchemaPrefixMigration.Outcome.MIGRATED);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_users", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("select nextval('ctxa_users_id_seq')", Long.class))
                .as("the sequence continues where it was").isEqualTo(3L);
        assertThat(jdbc.queryForList("select object_name from ctxa_schema_inventory_object where product_owner = 'OSS'", String.class))
                .as("the recorded ownership names the new table").containsExactly("ctxa_users");
        assertThat(jdbc.queryForList("select object_name from ctxa_schema_inventory_object where product_owner = 'HOST'", String.class))
                .as("a table of the application is not renamed in the record").containsExactly("orders");
        assertThat(new ContexaSchemaPrefixMigration(legacy).migrate()).isEqualTo(ContexaSchemaPrefixMigration.Outcome.NOT_NEEDED);

        DataSource fresh = inSchema(FRESH);
        install(fresh, "META-INF/contexa/db/schema.sql");
        Map<String, List<String>> migrated = shape(legacy, LEGACY);
        Map<String, List<String>> installed = shape(fresh, FRESH);
        for (String kind : installed.keySet()) {
            List<String> missing = new ArrayList<>(installed.get(kind));
            missing.removeAll(migrated.get(kind));
            List<String> extra = new ArrayList<>(migrated.get(kind));
            extra.removeAll(installed.get(kind));
            assertThat(missing).as("the %s a fresh installation has and the migrated database lacks", kind).isEmpty();
            assertThat(extra).as("the %s the migrated database has and a fresh installation lacks", kind).isEmpty();
        }
    }

    /** Tables, columns, sequences, indexes and constraints by name, for the comparison of two installations. */
    private static Map<String, List<String>> shape(DataSource dataSource, String schema) {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        Map<String, List<String>> shape = new LinkedHashMap<>();
        shape.put("tables", jdbc.queryForList("select tablename from pg_tables where schemaname = ? order by 1", String.class, schema));
        shape.put("columns", jdbc.queryForList("select table_name || '.' || column_name || ':' || data_type "
                + "from information_schema.columns where table_schema = ? order by 1", String.class, schema));
        shape.put("sequences", jdbc.queryForList("select sequencename from pg_sequences where schemaname = ? order by 1", String.class, schema));
        shape.put("indexes", cutNamesAlike(jdbc.queryForList("select indexname from pg_indexes where schemaname = ? order by 1",
                String.class, schema)));
        shape.put("constraints", cutNamesAlike(jdbc.queryForList("select c.conname from pg_constraint c "
                + "join pg_namespace n on n.oid = c.connamespace where n.nspname = ? order by 1", String.class, schema)));
        return shape;
    }

    /**
     * PostgreSQL cuts the names it makes itself (a unique key over several columns of a long table name) at 63
     * characters its own way, the migration keeps the cut name it found and shortens it by its own rule: such a name
     * is compared by the beginning of the table name in it, and every name still counts.
     */
    private static List<String> cutNamesAlike(List<String> names) {
        return names.stream().map(name -> name.length() > 55 ? name.substring(0, 25) : name).sorted().toList();
    }

    @Test
    void tablesOfAnApplicationWithTheOldNamesAreNeverTouched() throws Exception {
        DataSource host = inSchema(HOST);
        JdbcTemplate jdbc = new JdbcTemplate(host);
        jdbc.execute("create table users (id bigint primary key, username text)");
        jdbc.execute("create table role (id bigint primary key, name text)");
        jdbc.execute("create table audit_log (id bigint primary key, message text)");
        jdbc.update("insert into users values (1, 'host-user')");

        assertThat(new ContexaSchemaPrefixMigration(host).migrate()).isEqualTo(ContexaSchemaPrefixMigration.Outcome.NOT_CONTEXA);

        assertThat(jdbc.queryForList("select tablename from pg_tables where schemaname = ? order by 1", String.class, HOST))
                .containsExactly("audit_log", "role", "users");
        assertThat(jdbc.queryForObject("select username from users where id = 1", String.class)).isEqualTo("host-user");
    }

    @Test
    void aCompleteLegacyInstallationBesideTablesWithTheNewNamesStopsWithoutChangingAnything() throws Exception {
        DataSource legacy = inSchema(LEGACY);
        legacyInstallation(legacy);
        JdbcTemplate jdbc = new JdbcTemplate(legacy);
        jdbc.execute("create table ctxa_users (id bigint primary key)");

        assertThatThrownBy(() -> new ContexaSchemaPrefixMigration(legacy).migrate())
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("both the former names and the ctxa_ names");

        assertThat(jdbc.queryForObject("select count(*) from pg_tables where schemaname = ? and tablename = 'users'", Integer.class, LEGACY))
                .as("nothing was renamed").isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from pg_tables where schemaname = ? and tablename = 'ctxa_admin_menu'", Integer.class, LEGACY))
                .isZero();
    }

    @Test
    void anEmptyDatabaseIsLeftAlone() throws Exception {
        DataSource empty = inSchema(FRESH);

        assertThat(new ContexaSchemaPrefixMigration(empty).migrate()).isEqualTo(ContexaSchemaPrefixMigration.Outcome.NOT_NEEDED);
        assertThat(new JdbcTemplate(empty).queryForObject("select count(*) from pg_tables where schemaname = ?", Integer.class, FRESH)).isZero();
    }

    @Test
    void aNodeWaitsWhileAnotherHoldsTheMigrationLock() throws Exception {
        DataSource legacy = inSchema(LEGACY);
        legacyInstallation(legacy);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Connection holder = legacy.getConnection()) {
            holder.setAutoCommit(false);
            try (Statement lock = holder.createStatement()) {
                lock.execute("select pg_advisory_xact_lock(" + ContexaSchemaPrefixMigration.ADVISORY_LOCK + ")");
            }
            Future<ContexaSchemaPrefixMigration.Outcome> node = executor.submit(() -> new ContexaSchemaPrefixMigration(legacy).migrate());

            assertThatThrownBy(() -> node.get(1500, TimeUnit.MILLISECONDS))
                    .as("the node does not look at the database while another holds the lock").isInstanceOf(TimeoutException.class);
            assertThat(new JdbcTemplate(legacy).queryForObject(
                    "select count(*) from pg_tables where schemaname = ? and tablename = 'users'", Integer.class, LEGACY))
                    .as("nothing was moved while it waited").isEqualTo(1);

            holder.rollback();                                      // the other node is done: the lock goes with its transaction
            assertThat(node.get(60, TimeUnit.SECONDS)).isEqualTo(ContexaSchemaPrefixMigration.Outcome.MIGRATED);
        } finally {
            executor.shutdownNow();
        }
        assertThat(new JdbcTemplate(legacy).queryForObject(
                "select count(*) from pg_tables where schemaname = ? and tablename = 'ctxa_users'", Integer.class, LEGACY)).isEqualTo(1);
    }

    @Test
    void nodesThatStartTogetherMoveTheDatabaseOnceAndNoneFails() throws Exception {
        DataSource legacy = inSchema(LEGACY);
        legacyInstallation(legacy);
        int nodes = 4;
        ExecutorService executor = Executors.newFixedThreadPool(nodes);
        CyclicBarrier together = new CyclicBarrier(nodes);
        try {
            List<Future<ContexaSchemaPrefixMigration.Outcome>> starts = new ArrayList<>();
            for (int node = 0; node < nodes; node++) {
                starts.add(executor.submit(() -> {
                    together.await();
                    return new ContexaSchemaPrefixMigration(legacy).migrate();
                }));
            }
            List<ContexaSchemaPrefixMigration.Outcome> outcomes = new ArrayList<>();
            for (Future<ContexaSchemaPrefixMigration.Outcome> start : starts) {
                outcomes.add(start.get(120, TimeUnit.SECONDS));              // a node that failed would throw here
            }
            assertThat(outcomes).containsExactlyInAnyOrder(ContexaSchemaPrefixMigration.Outcome.MIGRATED,
                    ContexaSchemaPrefixMigration.Outcome.NOT_NEEDED, ContexaSchemaPrefixMigration.Outcome.NOT_NEEDED,
                    ContexaSchemaPrefixMigration.Outcome.NOT_NEEDED);
        } finally {
            executor.shutdownNow();
        }
        assertThat(new JdbcTemplate(legacy).queryForObject(
                "select count(*) from pg_tables where schemaname = ? and tablename = 'ctxa_users'", Integer.class, LEGACY)).isEqualTo(1);
    }

    @Test
    void aCutNameStaysAnIdentifierAndTwoCutNamesStayTwo() {
        String first = ContexaSchemaPrefixMigration.fit("ctxa_" + "a".repeat(80) + "_one");
        String second = ContexaSchemaPrefixMigration.fit("ctxa_" + "a".repeat(80) + "_two");

        assertThat(first).hasSizeLessThanOrEqualTo(63);
        assertThat(second).hasSizeLessThanOrEqualTo(63);
        assertThat(first).isNotEqualTo(second);
        assertThat(ContexaSchemaPrefixMigration.fit("ctxa_users")).isEqualTo("ctxa_users");
    }
}
