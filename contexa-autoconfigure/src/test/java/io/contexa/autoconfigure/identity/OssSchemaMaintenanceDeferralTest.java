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
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An older database is upgraded in place by an enterprise start: the OSS maintenance runs before the enterprise
 * migrations, so a statement can name a column that only those migrations add. Such a statement is put off until the
 * migrations have run instead of stopping the start; a statement that still fails then stops it with the reason.
 */
class OssSchemaMaintenanceDeferralTest {

    private static final String LEDGER = "ctxa_prompt_governance_release_ledger";
    private static final String IDENTITY_INDEX = "ctxa_idx_prompt_governance_release_identity";

    @Test
    void onlyAMissingColumnOrTableIsPutOff() {
        assertThat(IamSeedDataAutoConfiguration.isMissingObjectFailure(new SQLException("no column", "42703"))).isTrue();
        assertThat(IamSeedDataAutoConfiguration.isMissingObjectFailure(new SQLException("no table", "42P01"))).isTrue();
        assertThat(IamSeedDataAutoConfiguration.isMissingObjectFailure(new SQLException("syntax", "42601"))).isFalse();
        assertThat(IamSeedDataAutoConfiguration.isMissingObjectFailure(new SQLException("duplicate", "23505"))).isFalse();
        assertThat(IamSeedDataAutoConfiguration.isMissingObjectFailure(new SQLException("no state"))).isFalse();
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_UPGRADE_DB_URL", matches = ".+")
    void anIndexOnAColumnTheEnterpriseMigrationsAddWaitsForThem() throws Exception {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(System.getenv("CONTEXA_TEST_UPGRADE_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        assertThat(ContexaSchemaInventory.readDatabase(dataSource).tables())
                .as("this test only runs on an empty database").isEmpty();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);

        // A database older than the code: the release ledger exists without the two columns its identity index names.
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
        jdbc.execute("alter table " + LEDGER + " drop column template_key cascade");
        jdbc.execute("alter table " + LEDGER + " drop column contract_version cascade");
        assertThat(indexCount(jdbc)).as("the cascade removed the index with its columns").isZero();

        // Without the allowance the first such statement stops the start, as before.
        OssSchemaMaintenanceBacklog refused = new OssSchemaMaintenanceBacklog(dataSource);
        assertThatThrownBy(() -> IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(dataSource, refused, false))
                .hasMessageContaining(IDENTITY_INDEX);
        assertThat(refused.pendingCount()).isZero();

        // With the allowance the statement is put off and every other statement is applied.
        OssSchemaMaintenanceBacklog backlog = new OssSchemaMaintenanceBacklog(dataSource);
        IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(dataSource, backlog, true);
        assertThat(backlog.pendingCount()).isEqualTo(1);
        assertThat(indexCount(jdbc)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from pg_indexes where tablename = '" + LEDGER
                + "' and indexname = 'ctxa_idx_prompt_governance_release_current'", Integer.class)).isEqualTo(1);

        // A statement that still fails once the migrations are done stops the start and names itself.
        assertThatThrownBy(backlog::complete)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(IDENTITY_INDEX);
        assertThat(backlog.pendingCount()).isEqualTo(1);

        // The enterprise migrations add the columns; the put-off statement then runs once and the backlog is empty.
        jdbc.execute("alter table " + LEDGER + " add column template_key varchar(128), "
                + "add column contract_version varchar(128)");
        backlog.complete();
        assertThat(backlog.pendingCount()).isZero();
        assertThat(indexCount(jdbc)).isEqualTo(1);
        backlog.complete();
    }

    private static int indexCount(JdbcTemplate jdbc) {
        return jdbc.queryForObject("select count(*) from pg_indexes where tablename = '" + LEDGER
                + "' and indexname = '" + IDENTITY_INDEX + "'", Integer.class);
    }
}
