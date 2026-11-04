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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A1-6: an enterprise-managed database installed before an OSS table existed gains that table before the OSS
 * completeness check, and nothing else changes. It runs on the server of {@code CONTEXA_TEST_UPGRADE_DB_URL} (PostgreSQL
 * with pgvector), in an empty database of its own: the other upgrade tests leave their tables in the one that names.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_UPGRADE_DB_URL", matches = ".+")
class OssTableAdditionUpgradeTest {

    @Test
    void anEnterpriseManagedDatabaseGainsTheOssTablesItLacks() throws Exception {
        String url = System.getenv("CONTEXA_TEST_UPGRADE_DB_URL");
        String username = System.getenv("CONTEXA_TEST_DB_USERNAME");
        String password = System.getenv("CONTEXA_TEST_DB_PASSWORD");
        String database = "ctxa_table_addition_" + Long.toUnsignedString(System.nanoTime());
        JdbcTemplate server = new JdbcTemplate(new DriverManagerDataSource(url, username, password));
        server.execute("create database " + database);
        try {
            gainsTheOssTablesItLacks(new DriverManagerDataSource(
                    url.substring(0, url.lastIndexOf('/') + 1) + database, username, password));
        } finally {
            server.execute("drop database if exists " + database + " with (force)");
        }
    }

    private void gainsTheOssTablesItLacks(DriverManagerDataSource dataSource) throws Exception {
        assertThat(ContexaSchemaInventory.readDatabase(dataSource).tables())
                .as("this test only runs on an empty database").isEmpty();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        ContexaSchemaInventory.Snapshot oss = ContexaSchemaInventory.fromResources(
                OssSchemaGovernance.OSS_OWNER, List.of(new ClassPathResource("META-INF/contexa/db/schema.sql")));

        // A database installed before the agent registry existed, then taken over by an enterprise.
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
        jdbc.execute("drop table ctxa_agent_registration");
        // prompt_inspection_result.finding_kinds_json is added by an alter statement of the schema, not by the create table
        jdbc.execute("drop table ctxa_prompt_inspection_result cascade");
        jdbc.execute("create table host_orders (id bigint primary key)");
        assertThat(ContexaSchemaInventory.diff(oss, ContexaSchemaInventory.readDatabase(dataSource)).missingTables())
                .containsExactlyInAnyOrder("ctxa_agent_registration", "ctxa_prompt_inspection_result");

        IamSeedDataAutoConfiguration.createMissingOssTables(dataSource);
        IamSeedDataAutoConfiguration.createMissingOssTables(dataSource);

        ContexaSchemaInventory.Diff after = ContexaSchemaInventory.diff(oss, ContexaSchemaInventory.readDatabase(dataSource));
        assertThat(after.missingTables()).isEmpty();
        assertThat(after.additionalTables()).containsExactly("host_orders");
        assertThat(jdbc.queryForObject("select count(*) from information_schema.columns "
                + "where table_name = 'ctxa_prompt_inspection_result' and column_name = 'finding_kinds_json'",
                Integer.class)).as("the column an alter statement of the schema adds to the created table").isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from pg_indexes where tablename = 'ctxa_agent_registration' "
                + "and indexname in ('ctxa_ux_agent_registration_tenant_agent', 'ctxa_idx_agent_registration_last_seen')",
                Integer.class)).isEqualTo(2);
    }
}
