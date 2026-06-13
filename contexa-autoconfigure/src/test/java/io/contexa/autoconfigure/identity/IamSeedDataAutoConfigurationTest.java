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
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;
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
    @DisplayName("IAM seed data should run before demo persona JPA provisioning")
    void iamSeedDataRunsBeforePersonaProvisioning() throws NoSuchMethodException {
        Method runner = IamSeedDataAutoConfiguration.class.getDeclaredMethod("iamSeedDataRunner", DataSource.class);

        assertThat(runner.getAnnotation(Order.class))
                .as("IAM seed must run before demo persona runners so users_id_seq is synced first")
                .isNotNull()
                .extracting(Order::value)
                .isEqualTo(10);
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
                .contains("create table one_time_tokens")
                .contains("create index idx_one_time_tokens_username")
                .doesNotContain("owner to contexa_sim");
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
