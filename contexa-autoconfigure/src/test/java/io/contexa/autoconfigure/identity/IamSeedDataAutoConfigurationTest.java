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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
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
    @DisplayName("IAM canonical schema should be a single db/schema.sql resource")
    void iamCanonicalSchemaUsesSingleSchemaSqlResource() {
        assertThat(IamSeedDataAutoConfiguration.SCHEMA_LOCATIONS)
                .containsExactly("db/schema.sql");
        assertThat(new ClassPathResource("db/pqa-official-schema.sql").exists())
                .isFalse();
    }

    @Test
    @DisplayName("IAM canonical schema should include PQA run ledger before child ledger tables")
    void iamCanonicalSchemaCreatesPqaRunLedgerBeforeChildLedgers() throws Exception {
        String schema = new ClassPathResource("db/schema.sql")
                .getContentAsString(StandardCharsets.UTF_8);

        assertThat(schema)
                .contains("V20260414_01__verification_benchmark_publication_ledger.sql")
                .contains("V20260501_02__official_verification_jsonb_evidence_shadows.sql")
                .contains("V20260504_02__verification_ledger_jsonb_shadows.sql");
        assertThat(schema.indexOf("CREATE TABLE IF NOT EXISTS verification_run_ledger"))
                .isLessThan(schema.indexOf("CREATE TABLE IF NOT EXISTS verification_run_round_ledger"));
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
    @DisplayName("IAM schema maintenance should run before Contexa JPA validation")
    void iamSchemaMaintenanceRunsBeforeContexaJpaValidation() {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerBeanDefinition(
                IamSeedDataAutoConfiguration.CONTEXA_ENTITY_MANAGER_FACTORY_BEAN,
                new RootBeanDefinition(Object.class));
        beanFactory.registerBeanDefinition(
                IamSeedDataAutoConfiguration.IAM_SEED_DATA_INITIALIZER_BEAN,
                new RootBeanDefinition(Object.class));

        BeanFactoryPostProcessor postProcessor = IamSeedDataAutoConfiguration.iamSeedDataJpaDependencyConfigurer();
        postProcessor.postProcessBeanFactory(beanFactory);

        assertThat(beanFactory
                .getBeanDefinition(IamSeedDataAutoConfiguration.CONTEXA_ENTITY_MANAGER_FACTORY_BEAN)
                .getDependsOn())
                .contains(IamSeedDataAutoConfiguration.IAM_SEED_DATA_INITIALIZER_BEAN);
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
    @DisplayName("IAM schema initialization should strip UTF-8 BOM before executing SQL")
    void iamSchemaInitializationStripsUtf8Bom() {
        String sanitized = IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                "\uFEFFcreate extension if not exists vector;");

        assertThat(sanitized)
                .startsWith("create extension")
                .doesNotContain("\uFEFF");
    }

    @Test
    @DisplayName("IAM schema maintenance should replay only idempotent schema evolution statements")
    void iamSchemaMaintenanceExtractsOnlyIdempotentSchemaEvolutionStatements() {
        String sql = """
                create table users (id bigint primary key);

                create table if not exists ai_security_monitoring_session_summary (
                    session_id varchar(64) primary key
                );

                alter table ai_security_monitoring_session_summary
                    add column if not exists reset_by varchar(160);

                alter table hcad_detection_evaluation
                    add column if not exists actor_session_key varchar(128),
                    add column if not exists window_id varchar(64);

                create index if not exists idx_hcad_eval_window
                    on hcad_detection_evaluation (window_id);

                insert into admin_menu (id, label) values (1, 'skip');

                alter table users owner to contexa;
                """;

        String maintenanceSql = IamSeedDataAutoConfiguration.extractIdempotentSchemaMaintenanceSql(
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(sql));

        assertThat(maintenanceSql)
                .contains("create table if not exists users")
                .contains("create table if not exists ai_security_monitoring_session_summary")
                .contains("alter table ai_security_monitoring_session_summary")
                .contains("alter table hcad_detection_evaluation")
                .contains("add column if not exists actor_session_key")
                .contains("create index if not exists idx_hcad_eval_window")
                .doesNotContain("insert into admin_menu")
                .doesNotContain("owner to");
        assertThat(maintenanceSql.indexOf("create table if not exists ai_security_monitoring_session_summary"))
                .isLessThan(maintenanceSql.indexOf("alter table ai_security_monitoring_session_summary"));
    }

    @Test
    @DisplayName("IAM schema execution should keep dollar quoted functions as one statement")
    void iamSchemaExecutionKeepsDollarQuotedFunctionsAsOneStatement() {
        String sql = """
                CREATE OR REPLACE FUNCTION contexa_test_notice()
                RETURNS TEXT
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    RETURN 'a;b';
                END;
                $function$;

                CREATE TABLE IF NOT EXISTS contexa_test_table (id BIGINT);
                """;

        assertThat(IamSeedDataAutoConfiguration.splitSqlStatements(sql))
                .hasSize(2)
                .first()
                .asString()
                .contains("RETURN 'a;b'")
                .contains("$function$");
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

        assertThat(expectedField.getInt(null)).isEqualTo(688);
    }

    @Test
    @DisplayName("IAM PQA official completeness check should require customer-facing metric contracts")
    void pqaOfficialCompletenessRequiresCustomerFacingMetricContracts() throws Exception {
        assertThat(privateStaticInt("EXPECTED_OFFICIAL_METRIC_PURPOSE_CONTRACTS")).isEqualTo(12);
        assertThat(privateStaticInt("EXPECTED_OFFICIAL_METRIC_INPUT_CONTRACTS")).isEqualTo(396);
        assertThat(privateStaticInt("EXPECTED_OFFICIAL_METRIC_CHECK_DISPLAY_EVIDENCE_CONTRACTS")).isEqualTo(66);
        assertThat(privateStaticInt("EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_CONTRACTS")).isEqualTo(390);
        assertThat(privateStaticInt("EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_BINDINGS")).isEqualTo(212);
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
    @DisplayName("IAM schema marker should include HCAD evaluation table in canonical schema")
    void iamSchemaMarkerIncludesHcadEvaluationTable() {
        assertThat(IamSeedDataAutoConfiguration.SCHEMA_MARKER_TABLES)
                .contains("hcad_detection_evaluation");
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

    private int privateStaticInt(String fieldName) throws Exception {
        Field field = IamSeedDataAutoConfiguration.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.getInt(null);
    }
}
