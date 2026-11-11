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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The decision for URLs no policy names, as a real PostgreSQL database keeps it: a new installation holds none until an
 * operator saves one (the column is NULL, so the configured decision or the signed-in default applies), and an
 * installation that already stored a decision keeps it through the start of a newer version, whether an operator chose it
 * or the column default of an older version put it there. The column loses its default and its NOT NULL constraint on the
 * way. Each case has a database of its own: nothing another test left in a shared schema is on its search path.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_UPGRADE_DB_URL", matches = ".+")
class NoMatchingUrlDecisionSeedPostgresTest {

    private static final String SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final String SETTINGS_SEED = "META-INF/contexa/db/data-system-settings.sql";
    private final List<String> databases = new ArrayList<>();

    @BeforeEach
    void noDatabasesYet() {
        databases.clear();
    }

    @AfterEach
    void dropDatabases() {
        JdbcTemplate admin = new JdbcTemplate(database("postgres"));
        for (String name : databases) {
            admin.queryForList("select pg_terminate_backend(pid) from pg_stat_activity where datname = ?", name);
            admin.execute("drop database if exists " + name);
        }
    }

    /** An empty database with the extension the schema needs, as an operator prepares it. */
    private DataSource newDatabase() {
        String name = "contexa_fx6_" + UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
        new JdbcTemplate(database("postgres")).execute("create database " + name);
        databases.add(name);
        DataSource dataSource = database(name);
        new JdbcTemplate(dataSource).execute("create extension if not exists vector");
        return dataSource;
    }

    @Test
    void aNewInstallationHoldsNoDecisionSoTheSignedInDefaultApplies() throws Exception {
        DataSource fresh = newDatabase();
        install(fresh, schemaText());
        seedSettings(fresh);

        JdbcTemplate jdbc = new JdbcTemplate(fresh);
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .as("nobody chose a decision").isNull();
        assertThat(jdbc.queryForObject("select missing_method_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("PERMIT");
        assertThat(urlDecisionColumn(jdbc)).isEqualTo("YES none");
    }

    /** Installed while PERMIT was the default (the seed row took it from the column), then started with this version. */
    @Test
    void anInstallationThatStoredPermitKeepsItThroughTheNextStart() throws Exception {
        DataSource installed = installedWithColumnDefault("PERMIT");
        JdbcTemplate jdbc = new JdbcTemplate(installed);
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("PERMIT");
        assertThat(urlDecisionColumn(jdbc)).as("as the older version made it").isEqualTo("NO default");

        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(installed, new OssSchemaMaintenanceBacklog(installed), false);
        seedSettings(installed);

        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .as("nothing is changed without a choice").isEqualTo("PERMIT");
        assertThat(jdbc.queryForObject("select count(*) from ctxa_system_settings", Integer.class)).isEqualTo(1);
        assertThat(urlDecisionColumn(jdbc)).as("the column no longer decides for a row that is written without it")
                .isEqualTo("YES none");
    }

    /** Installed by the version whose column default was AUTHENTICATED, then started with this version. */
    @Test
    void anInstallationThatStoredAuthenticatedKeepsItThroughTheNextStart() throws Exception {
        DataSource installed = installedWithColumnDefault("AUTHENTICATED");
        JdbcTemplate jdbc = new JdbcTemplate(installed);
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("AUTHENTICATED");

        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(installed, new OssSchemaMaintenanceBacklog(installed), false);
        seedSettings(installed);

        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("AUTHENTICATED");
        assertThat(urlDecisionColumn(jdbc)).isEqualTo("YES none");
    }

    /** The upgrade is idempotent: a start after the column was changed neither fails nor writes a decision. */
    @Test
    void theColumnChangeCanBeReplayedAndNeverFillsARowThatHoldsNone() throws Exception {
        DataSource fresh = newDatabase();
        install(fresh, schemaText());
        seedSettings(fresh);
        for (int start = 0; start < 3; start++) {
            IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(fresh, new OssSchemaMaintenanceBacklog(fresh), false);
            seedSettings(fresh);
        }

        JdbcTemplate jdbc = new JdbcTemplate(fresh);
        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class)).isNull();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_system_settings", Integer.class)).isEqualTo(1);
        assertThat(urlDecisionColumn(jdbc)).isEqualTo("YES none");
    }

    /** A database that never had the column gains it unset: the row an older version wrote holds no decision. */
    @Test
    void aDatabaseOfAVersionWithoutTheColumnGainsItUnset() throws Exception {
        DataSource installed = installedWithoutTheColumn();
        JdbcTemplate jdbc = new JdbcTemplate(installed);
        assertThat(jdbc.queryForObject("select count(*) from information_schema.columns where table_schema = current_schema() "
                + "and table_name = 'ctxa_system_settings' and column_name = 'no_matching_url_policy_decision'", Integer.class))
                .isZero();

        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(installed, new OssSchemaMaintenanceBacklog(installed), false);
        seedSettings(installed);

        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class)).isNull();
        assertThat(urlDecisionColumn(jdbc)).isEqualTo("YES none");
    }

    /** A database of the names before ctxa_, with the settings row of that time, moved and started with this version. */
    @Test
    void aLegacyInstallationKeepsTheDecisionItStored() throws Exception {
        DataSource legacy = newDatabase();
        String legacySchema = "db/schema-before-ctxa-prefix.sql";
        IamSeedDataAutoConfiguration.executeSchemaSql(legacy, legacySchema,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource(legacySchema).getContentAsString(StandardCharsets.UTF_8)));
        JdbcTemplate jdbc = new JdbcTemplate(legacy);
        jdbc.update("insert into system_settings (audit_log_retention_days, default_role, policy_combining_algorithm, "
                + "registration_enabled, created_at) values (90, 'ROLE_USER', 'FIRST_APPLICABLE', false, current_timestamp)");

        assertThat(new ContexaSchemaPrefixMigration(legacy).migrate()).isEqualTo(ContexaSchemaPrefixMigration.Outcome.MIGRATED);
        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(legacy, new OssSchemaMaintenanceBacklog(legacy), false);
        seedSettings(legacy);

        assertThat(jdbc.queryForObject("select no_matching_url_policy_decision from ctxa_system_settings", String.class))
                .isEqualTo("PERMIT");
        assertThat(urlDecisionColumn(jdbc)).isEqualTo("YES none");
    }

    /** The schema as an older version installed it: the column with a default and NOT NULL, the seed row taking the default. */
    private DataSource installedWithColumnDefault(String columnDefault) throws Exception {
        String schema = schemaText();
        String unset = "(?m)^alter table ctxa_system_settings .*no_matching_url_policy_decision.*;\\s*$";
        assertThat(schema).containsPattern(unset);
        DataSource installed = newDatabase();
        install(installed, schema.replaceAll(unset, "") + "\nalter table ctxa_system_settings add column if not exists "
                + "no_matching_url_policy_decision varchar(20) default '" + columnDefault + "' not null;\n");
        seedSettings(installed);
        return installed;
    }

    /** The schema of a version that had no such column, with the row its seed wrote. */
    private DataSource installedWithoutTheColumn() throws Exception {
        String unset = "(?m)^alter table ctxa_system_settings .*no_matching_url_policy_decision.*;\\s*$";
        DataSource installed = newDatabase();
        install(installed, schemaText().replaceAll(unset, ""));
        seedSettings(installed);
        return installed;
    }

    /** Whether the column takes NULL and what it defaults to, as the catalog says. */
    private static String urlDecisionColumn(JdbcTemplate jdbc) {
        return jdbc.queryForObject("select is_nullable || ' ' || case when column_default is null then 'none' else 'default' end "
                + "from information_schema.columns where table_schema = current_schema() and table_name = 'ctxa_system_settings' "
                + "and column_name = 'no_matching_url_policy_decision'", String.class);
    }

    private static String schemaText() throws Exception {
        return new ClassPathResource(SCHEMA).getContentAsString(StandardCharsets.UTF_8);
    }

    private static void install(DataSource dataSource, String schema) throws Exception {
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, SCHEMA,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(schema));
    }

    private static void seedSettings(DataSource dataSource) {
        IamSeedDataAutoConfiguration.seedPopulator(new ClassPathResource(SETTINGS_SEED)).execute(dataSource);
    }

    private static DataSource database(String name) {
        String url = System.getenv("CONTEXA_TEST_UPGRADE_DB_URL");
        int query = url.indexOf('?');
        String base = query >= 0 ? url.substring(0, query) : url;
        String rest = query >= 0 ? url.substring(query) : "";
        String target = base.substring(0, base.lastIndexOf('/') + 1) + name + rest;
        return new DriverManagerDataSource(target, System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
    }
}
