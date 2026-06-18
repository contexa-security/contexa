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

import static org.assertj.core.api.Assertions.assertThat;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.springframework.beans.factory.InitializingBean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

class IamSeedDataAutoConfigurationTest {

    @Test
    @DisplayName("IAM SQL resources should not be exposed at Spring Boot SQL init default locations")
    void iamSqlResourcesAreNotExposedAtSpringBootSqlInitDefaultLocations() {
        assertThat(new ClassPathResource("data.sql").exists()).isFalse();
        assertThat(new ClassPathResource("schema.sql").exists()).isFalse();
        assertThat(new ClassPathResource("data-menu.sql").exists()).isFalse();
    }

    @Test
    @DisplayName("IAM seed data should be exposed as an InitializingBean")
    void iamSeedDataIsExposedAsInitializingBean() throws NoSuchMethodException {
        Method initializer = IamSeedDataAutoConfiguration.class.getDeclaredMethod("iamSeedDataInitializer", DataSource.class);

        assertThat(initializer.getReturnType())
                .as("IAM seed must run during bean initialization against contexaDataSource")
                .isEqualTo(InitializingBean.class);
    }

    @Test
    @DisplayName("IAM schema initialization should strip environment-specific owner statements")
    void iamSchemaInitializationStripsOwnerStatements() {
        String sql = """
                create table one_time_tokens
                (
                    token_value varchar(36) not null
                        primary key
                );

                alter table one_time_tokens
                    owner to contexa_sim;

                create index idx_one_time_tokens_username
                    on one_time_tokens (token_value);
                """;

        String sanitized = IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(sql);

        assertThat(sanitized)
                .contains("create table if not exists one_time_tokens")
                .contains("create index if not exists idx_one_time_tokens_username")
                .doesNotContain("owner to contexa_sim");
    }

    @Test
    @DisplayName("IAM PQA official completeness check should run after seed SQL")
    void pqaOfficialCompletenessCheckRunsAfterSeedSql() throws Exception {
        String source = Files.readString(Path.of(
                "src/main/java/io/contexa/autoconfigure/identity/IamSeedDataAutoConfiguration.java"));

        assertThat(source.indexOf("for (String location : SEED_LOCATIONS)"))
                .isLessThan(source.indexOf("completePqaOfficialSchemaIfNeeded(dataSource);"));
    }

    @Test
    @DisplayName("IAM PQA official completeness check should require every prompt signal contract")
    void pqaOfficialCompletenessRequiresEveryPromptSignalContract() throws Exception {
        Field expectedField = IamSeedDataAutoConfiguration.class
                .getDeclaredField("EXPECTED_OFFICIAL_PROMPT_SIGNAL_CONTRACTS");
        expectedField.setAccessible(true);

        assertThat(expectedField.getInt(null)).isEqualTo(677);
    }

    @Test
    @DisplayName("IAM schema initialization should skip DDL when CLI already installed the schema")
    void iamSchemaInitializationSkipsDdlWhenSchemaIsAlreadyInstalled() {
        Set<String> allMarkers = Arrays.stream(IamSeedDataAutoConfiguration.SCHEMA_MARKER_TABLES)
                .collect(Collectors.toSet());

        assertThat(IamSeedDataAutoConfiguration.schemaInstallStateForMarkers(allMarkers))
                .isEqualTo(IamSeedDataAutoConfiguration.SchemaInstallState.COMPLETE);
    }

    @Test
    @DisplayName("IAM schema initialization should execute DDL only for an empty Contexa schema")
    void iamSchemaInitializationExecutesDdlOnlyForEmptySchema() {
        assertThat(IamSeedDataAutoConfiguration.schemaInstallStateForMarkers(Set.of()))
                .isEqualTo(IamSeedDataAutoConfiguration.SchemaInstallState.ABSENT);
    }

    @Test
    @DisplayName("IAM schema initialization should fail fast for partial schema installs")
    void iamSchemaInitializationRejectsPartialSchema() {
        assertThat(IamSeedDataAutoConfiguration.schemaInstallStateForMarkers(Set.of("users")))
                .isEqualTo(IamSeedDataAutoConfiguration.SchemaInstallState.PARTIAL);
    }
}
