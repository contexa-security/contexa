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
import io.contexa.contexacore.verification.metric.OfficialVerificationDefinitionCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import static org.assertj.core.api.Assertions.assertThat;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.sql.DataSource;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.InitializingBean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
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
        Method initializer = IamSeedDataAutoConfiguration.class.getDeclaredMethod(
                "iamSeedDataInitializer", DataSource.class, OssSchemaGovernance.class, Environment.class);

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
                String.valueOf((char) 0xFEFF) + "create extension if not exists vector;");

        assertThat(sanitized)
                .startsWith("create extension")
                .doesNotContain(String.valueOf((char) 0xFEFF));
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

                alter table ai_security_decision_observation
                    add column if not exists actor_session_key varchar(128),
                    add column if not exists window_id varchar(64);

                create index if not exists idx_ai_decision_observation_window
                    on ai_security_decision_observation (window_id);

                insert into admin_menu (id, label) values (1, 'skip');

                alter table users owner to contexa;
                """;

        String maintenanceSql = IamSeedDataAutoConfiguration.extractIdempotentSchemaMaintenanceSql(
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(sql));

        assertThat(maintenanceSql)
                .contains("create table if not exists users")
                .contains("create table if not exists ai_security_monitoring_session_summary")
                .contains("alter table ai_security_monitoring_session_summary")
                .contains("alter table ai_security_decision_observation")
                .contains("add column if not exists actor_session_key")
                .contains("create index if not exists idx_ai_decision_observation_window")
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
    @DisplayName("IAM derives the versioned 12 metric and 66 check definition view from the canonical contract")
    void pqaOfficialDefinitionCatalogIsVersionedAndKeyBacked() {
        FinalPromptMetricContractCatalog canonical = FinalPromptMetricContractCatalog.load(new ObjectMapper());
        assertThat(OfficialVerificationDefinitionCatalog.metrics()).hasSize(12);
        assertThat(OfficialVerificationDefinitionCatalog.checks()).hasSize(66);
        assertThat(OfficialVerificationDefinitionCatalog.VERSION).isEqualTo(canonical.contractVersion());
        assertThat(OfficialVerificationDefinitionCatalog.metrics())
                .extracting(OfficialVerificationDefinitionCatalog.MetricSeed::code)
                .containsExactlyElementsOf(canonical.metricCodesInOrder());
        assertThat(OfficialVerificationDefinitionCatalog.checks())
                .extracting(check -> check.metricCode() + "|" + check.checkCode())
                .containsExactlyElementsOf(canonical.metrics().stream()
                        .flatMap(metric -> metric.checks().stream())
                        .map(check -> check.metricCode() + "|" + check.checkName())
                        .toList());
        assertThat(OfficialVerificationDefinitionCatalog.metrics())
                .extracting(OfficialVerificationDefinitionCatalog.MetricSeed::code)
                .contains("COR")
                .doesNotContain("CoR");
        assertThat(OfficialVerificationDefinitionCatalog.checksum()).matches("[a-f0-9]{64}");
    }

    @Test
    @DisplayName("IAM canonical schema inventory includes versioned OSS provenance")
    void iamSchemaInventoryIncludesProvenance() throws Exception {
        ContexaSchemaInventory.Snapshot inventory = ContexaSchemaInventory.fromResources(
                "OSS", List.of(new ClassPathResource("db/schema.sql")));

        assertThat(inventory.tables()).contains(
                "contexa_schema_provenance",
                "contexa_schema_inventory_object");
        assertThat(inventory.version()).startsWith("oss-");
        assertThat(inventory.checksum()).matches("[a-f0-9]{64}");
    }

    @Test
    @DisplayName("Schema inventory resolves ordered create, drop, and rename DDL to the final state")
    void schemaInventoryResolvesFinalDdlState() throws Exception {
        ByteArrayResource first = new ByteArrayResource("""
                create table first_table (id bigint);
                create view first_view as select id from first_table;
                create table old_name (id bigint);
                """.getBytes(StandardCharsets.UTF_8), "01-create.sql");
        ByteArrayResource second = new ByteArrayResource("""
                drop table if exists first_table;
                drop view if exists first_view;
                alter table old_name rename to final_name;
                """.getBytes(StandardCharsets.UTF_8), "02-transform.sql");

        ContexaSchemaInventory.Snapshot inventory = ContexaSchemaInventory.fromResources(
                "ENTERPRISE", List.of(second, first));

        assertThat(inventory.tables()).containsExactly("final_name");
        assertThat(inventory.views()).isEmpty();
    }

    @Test
    @DisplayName("Database ownership inventory is deterministic and separates host from unowned objects")
    void databaseOwnershipInventorySeparatesHostAndUnownedObjects() {
        ContexaSchemaInventory.DatabaseObjects actual = new ContexaSchemaInventory.DatabaseObjects(
                Set.of("oss_table", "orders", "official_verification_oss_run"),
                Set.of("host_view"));
        ContexaSchemaInventory.Snapshot oss = ContexaSchemaInventory.fromDatabaseObjects(
                "OSS", new ContexaSchemaInventory.DatabaseObjects(Set.of("oss_table"), Set.of()));
        ContexaSchemaInventory.Snapshot host = ContexaSchemaInventory.fromDatabaseObjects(
                "HOST", new ContexaSchemaInventory.DatabaseObjects(Set.of("orders"), Set.of("host_view")));

        ContexaSchemaInventory.DatabaseObjects unowned = ContexaSchemaInventory.subtract(
                actual, List.of(oss, host));
        ContexaSchemaInventory.Snapshot first = ContexaSchemaInventory.fromDatabaseObjects(
                "LEGACY_UNOWNED", unowned);
        ContexaSchemaInventory.Snapshot second = ContexaSchemaInventory.fromDatabaseObjects(
                "LEGACY_UNOWNED",
                new ContexaSchemaInventory.DatabaseObjects(
                        Set.of("official_verification_oss_run"), Set.of()));

        assertThat(host.tables()).containsExactlyInAnyOrder("orders");
        assertThat(unowned.tables()).containsExactlyInAnyOrder("official_verification_oss_run");
        assertThat(first.version()).isEqualTo(second.version());
        assertThat(first.checksum()).isEqualTo(second.checksum());
    }

    @Test
    @DisplayName("OSS handoff accepts a version upgrade only when the recorded owned object set is unchanged")
    void ossHandoffVersionUpgradeRequiresSameOwnedObjects() {
        ContexaSchemaInventory.Snapshot current = new ContexaSchemaInventory.Snapshot(
                "OSS", "oss-current", "current-checksum",
                Set.of("users", "policy"), Set.of("policy_view"), Set.of());
        ContexaSchemaInventory.Snapshot historical = new ContexaSchemaInventory.Snapshot(
                "OSS", "oss-historical", "historical-checksum",
                Set.of("policy", "users"), Set.of("policy_view"), Set.of());
        ContexaSchemaInventory.Snapshot incomplete = new ContexaSchemaInventory.Snapshot(
                "OSS", "oss-historical", "historical-checksum",
                Set.of("users"), Set.of("policy_view"), Set.of());

        assertThat(OssSchemaGovernance.sameOwnedObjects(current, historical)).isTrue();
        assertThat(OssSchemaGovernance.sameOwnedObjects(current, incomplete)).isFalse();
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

    @Test
    @DisplayName("Enterprise provenance prevents OSS canonical DDL maintenance on restart")
    void enterpriseRestartDoesNotReapplyOssCanonicalDdl() {
        assertThat(IamSeedDataAutoConfiguration.shouldApplyCanonicalSchemaMaintenance(
                IamSeedDataAutoConfiguration.SchemaInstallState.COMPLETE, true)).isFalse();
        assertThat(IamSeedDataAutoConfiguration.shouldApplyCanonicalSchemaMaintenance(
                IamSeedDataAutoConfiguration.SchemaInstallState.COMPLETE, false)).isTrue();
        assertThat(IamSeedDataAutoConfiguration.shouldApplyCanonicalSchemaMaintenance(
                IamSeedDataAutoConfiguration.SchemaInstallState.ABSENT, false)).isFalse();
    }

    @Test
    @DisplayName("Direct Enterprise startup rejects an unverified non-empty database before DDL")
    void directEnterpriseStartupRejectsUnverifiedNonEmptyDatabase() {
        ContexaSchemaInventory.DatabaseObjects unknown = new ContexaSchemaInventory.DatabaseObjects(
                Set.of("host_only_marker"), Set.of());
        ContexaSchemaInventory.DatabaseObjects empty = new ContexaSchemaInventory.DatabaseObjects(
                Set.of(), Set.of());

        assertThat(IamSeedDataAutoConfiguration.shouldRejectUnverifiedEnterpriseSchema(
                true, false, IamSeedDataAutoConfiguration.SchemaInstallState.ABSENT, unknown)).isTrue();
        assertThat(IamSeedDataAutoConfiguration.shouldRejectUnverifiedEnterpriseSchema(
                true, false, IamSeedDataAutoConfiguration.SchemaInstallState.ABSENT, empty)).isFalse();
        assertThat(IamSeedDataAutoConfiguration.shouldRejectUnverifiedEnterpriseSchema(
                true, true, IamSeedDataAutoConfiguration.SchemaInstallState.COMPLETE, unknown)).isFalse();
        assertThat(IamSeedDataAutoConfiguration.shouldRejectUnverifiedEnterpriseSchema(
                false, false, IamSeedDataAutoConfiguration.SchemaInstallState.ABSENT, unknown)).isFalse();
    }

    private int privateStaticInt(String fieldName) throws Exception {
        Field field = IamSeedDataAutoConfiguration.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.getInt(null);
    }
}
