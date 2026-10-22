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
 * completeness check, and nothing else changes. It runs only against the empty database named by
 * {@code CONTEXA_TEST_UPGRADE_DB_URL} (PostgreSQL with pgvector) and refuses any database that is not empty.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_UPGRADE_DB_URL", matches = ".+")
class OssTableAdditionUpgradeTest {

    @Test
    void anEnterpriseManagedDatabaseGainsTheOssTablesItLacks() throws Exception {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(System.getenv("CONTEXA_TEST_UPGRADE_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        assertThat(ContexaSchemaInventory.readDatabase(dataSource).tables())
                .as("this test only runs on an empty database").isEmpty();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        ContexaSchemaInventory.Snapshot oss = ContexaSchemaInventory.fromResources(
                OssSchemaGovernance.OSS_OWNER, List.of(new ClassPathResource("db/schema.sql")));

        // A database installed before the agent registry existed, then taken over by an enterprise.
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, "db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
        jdbc.execute("drop table agent_registration");
        jdbc.execute("create table host_orders (id bigint primary key)");
        assertThat(ContexaSchemaInventory.diff(oss, ContexaSchemaInventory.readDatabase(dataSource)).missingTables())
                .containsExactly("agent_registration");

        IamSeedDataAutoConfiguration.createMissingOssTables(dataSource);
        IamSeedDataAutoConfiguration.createMissingOssTables(dataSource);

        ContexaSchemaInventory.Diff after = ContexaSchemaInventory.diff(oss, ContexaSchemaInventory.readDatabase(dataSource));
        assertThat(after.missingTables()).isEmpty();
        assertThat(after.additionalTables()).containsExactly("host_orders");
        assertThat(jdbc.queryForObject("select count(*) from pg_indexes where tablename = 'agent_registration' "
                + "and indexname in ('ux_agent_registration_tenant_agent', 'idx_agent_registration_last_seen')",
                Integer.class)).isEqualTo(2);
    }
}
