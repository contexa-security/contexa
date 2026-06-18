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

import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, CoreDataAutoConfiguration.class})
@ConditionalOnClass(DataSource.class)
@ConditionalOnBean(value = PlatformConfig.class, name = "contexaDataSource")
@ConditionalOnProperty(prefix = "contexa.iam.seed", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamSeedDataAutoConfiguration {

    private static final String PQA_OFFICIAL_SCHEMA_LOCATION = "db/pqa-official-schema.sql";
    private static final int EXPECTED_OFFICIAL_METRIC_EVALUATION_CONTRACTS = 66;
    private static final int EXPECTED_OFFICIAL_PROMPT_SIGNAL_CONTRACTS = 677;
    private static final int EXPECTED_OFFICIAL_VERIFICATION_METRIC_DEFINITIONS = 12;
    private static final int EXPECTED_OFFICIAL_VERIFICATION_METRIC_CHECK_DEFINITIONS = 12;

    static final String[] SCHEMA_LOCATIONS = {
            "db/schema.sql",
            PQA_OFFICIAL_SCHEMA_LOCATION
    };

    static final String[] SCHEMA_MARKER_TABLES = {
            "users",
            "admin_menu",
            "sealed_evidence_package",
            "official_metric_evaluation_contract",
            "official_prompt_signal_contract",
            "verification_run_ledger",
            "official_verification_run_batch",
            "official_verification_metric_snapshot",
            "official_metric_purpose_contract",
            "official_metric_purpose_evidence_ledger",
            "official_actual_prompt_problem_ledger",
            "official_verification_prompt_comparison",
            "pqa_sealed_evidence_resource_status"
    };

    static final String[] SEED_LOCATIONS = {
            "db/data.sql",
            "db/data-menu.sql",
            "db/data-system-settings.sql"
    };

    @Bean(name = "iamSeedDataInitializer")
    public InitializingBean iamSeedDataInitializer(@Qualifier("contexaDataSource") DataSource dataSource) {
        return () -> initializeSchemaAndSeedData(dataSource);
    }

    private void initializeSchemaAndSeedData(DataSource dataSource) throws SQLException, IOException {
        SchemaInstallState schemaInstallState = detectSchemaInstallState(dataSource);
        if (schemaInstallState == SchemaInstallState.ABSENT || schemaInstallState == SchemaInstallState.PARTIAL) {
            if (schemaInstallState == SchemaInstallState.PARTIAL) {
                log.warn("[IamSeedData] Contexa schema is partially installed; attempting idempotent completion");
            }
            for (String location : SCHEMA_LOCATIONS) {
                Resource schema = new ClassPathResource(location);
                if (!schema.exists()) {
                    log.warn("[IamSeedData] classpath:{} not found, skipping schema initialization", location);
                    continue;
                }
                ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
                populator.setContinueOnError(false);
                populator.addScript(sanitizedSchemaResource(location, schema));
                populator.execute(dataSource);
                log.info("[IamSeedData] {} executed", location);
            }
            SchemaInstallState completedState = detectSchemaInstallState(dataSource);
            if (completedState != SchemaInstallState.COMPLETE) {
                throw new IllegalStateException(
                        "Contexa schema is partially installed after canonical schema execution. "
                                + "Rebuild the Contexa database or run the canonical "
                                + "db/schema.sql and db/pqa-official-schema.sql manually before starting the application.");
            }
        } else if (schemaInstallState == SchemaInstallState.COMPLETE) {
            log.info("[IamSeedData] Contexa schema already installed, skipping schema initialization");
        }
        for (String location : SEED_LOCATIONS) {
            Resource seed = new ClassPathResource(location);
            if (!seed.exists()) {
                log.warn("[IamSeedData] classpath:{} not found, skipping", location);
                continue;
            }
            ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
            populator.setContinueOnError(false);
            populator.addScript(seed);
            populator.execute(dataSource);
            log.info("[IamSeedData] {} executed", location);
        }
        completePqaOfficialSchemaIfNeeded(dataSource);
    }

    private void completePqaOfficialSchemaIfNeeded(DataSource dataSource) throws SQLException, IOException {
        PqaOfficialSeedState seedState = detectPqaOfficialSeedState(dataSource);
        if (seedState == PqaOfficialSeedState.COMPLETE) {
            return;
        }
        Resource schema = new ClassPathResource(PQA_OFFICIAL_SCHEMA_LOCATION);
        if (!schema.exists()) {
            log.warn("[IamSeedData] classpath:{} not found, cannot complete PQA official schema seed",
                    PQA_OFFICIAL_SCHEMA_LOCATION);
            return;
        }
        log.warn("[IamSeedData] PQA official schema seed is {}; attempting idempotent completion", seedState);
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.setContinueOnError(false);
        populator.addScript(pqaSeedCompletionSchemaResource(schema));
        populator.execute(dataSource);
        PqaOfficialSeedState completedState = detectPqaOfficialSeedState(dataSource);
        if (completedState != PqaOfficialSeedState.COMPLETE) {
            throw new IllegalStateException(
                    "PQA official schema seed is incomplete after canonical db/pqa-official-schema.sql execution. "
                            + "Rebuild the Contexa database or run the canonical "
                            + "db/pqa-official-schema.sql manually before starting the application.");
        }
        log.info("[IamSeedData] {} executed for PQA official seed completion", PQA_OFFICIAL_SCHEMA_LOCATION);
    }

    private Resource pqaSeedCompletionSchemaResource(Resource schema) throws IOException {
        String sql = schema.getContentAsString(StandardCharsets.UTF_8);
        String sanitizedSql = sanitizeSchemaSqlForInstalledDatabase(sql)
                .replaceAll("(?is)\\balter\\s+table\\s+\\S+\\s+alter\\s+column\\s+\\S+\\s+set\\s+data\\s+type\\s+[^;]+;\\s*", "");
        return new ByteArrayResource(sanitizedSql.getBytes(StandardCharsets.UTF_8), PQA_OFFICIAL_SCHEMA_LOCATION);
    }

    private PqaOfficialSeedState detectPqaOfficialSeedState(DataSource dataSource) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            if (!tableExists(connection, metadata, "official_metric_purpose_contract")
                    || !tableExists(connection, metadata, "official_metric_evaluation_contract")
                    || !tableExists(connection, metadata, "official_metric_customer_display_contract")
                    || !tableExists(connection, metadata, "official_metric_check_display_evidence_contract")
                    || !tableExists(connection, metadata, "official_prompt_signal_contract")
                    || !tableExists(connection, metadata, "official_verification_metric_definition")
                    || !tableExists(connection, metadata, "official_verification_metric_check_definition")) {
                return PqaOfficialSeedState.ABSENT;
            }
            return countRows(connection, "official_metric_evaluation_contract")
                    >= EXPECTED_OFFICIAL_METRIC_EVALUATION_CONTRACTS
                    && countRows(connection, "official_prompt_signal_contract")
                    >= EXPECTED_OFFICIAL_PROMPT_SIGNAL_CONTRACTS
                    && countRows(connection, "official_verification_metric_definition")
                    >= EXPECTED_OFFICIAL_VERIFICATION_METRIC_DEFINITIONS
                    && countRows(connection, "official_verification_metric_check_definition")
                    >= EXPECTED_OFFICIAL_VERIFICATION_METRIC_CHECK_DEFINITIONS
                    ? PqaOfficialSeedState.COMPLETE
                    : PqaOfficialSeedState.PARTIAL;
        }
    }

    private int countRows(Connection connection, String tableName) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery("select count(*) from " + tableName)) {
            return resultSet.next() ? resultSet.getInt(1) : 0;
        }
    }

    private Resource sanitizedSchemaResource(String location, Resource schema) throws IOException {
        String sql = schema.getContentAsString(StandardCharsets.UTF_8);
        String sanitizedSql = sanitizeSchemaSqlForInstalledDatabase(sql);
        return new ByteArrayResource(sanitizedSql.getBytes(StandardCharsets.UTF_8), location);
    }

    static String sanitizeSchemaSqlForInstalledDatabase(String sql) {
        if (sql == null || sql.isBlank()) {
            return "";
        }
        return sql
                .replaceAll("(?is)\\balter\\s+(table|sequence|view|materialized\\s+view|index)\\s+[^;]+?\\s+owner\\s+to\\s+[^;]+;\\s*", "")
                .replaceAll("(?im)^\\s*create\\s+table\\s+(?!if\\s+not\\s+exists\\b)", "create table if not exists ")
                .replaceAll("(?im)^\\s*create\\s+sequence\\s+(?!if\\s+not\\s+exists\\b)", "create sequence if not exists ")
                .replaceAll("(?im)^\\s*create\\s+(unique\\s+)?index\\s+(?!if\\s+not\\s+exists\\b)", "create $1index if not exists ");
    }

    private SchemaInstallState detectSchemaInstallState(@Qualifier("contexaDataSource") DataSource dataSource)
            throws SQLException {
        Set<String> presentTables = new LinkedHashSet<>();
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            for (String tableName : SCHEMA_MARKER_TABLES) {
                if (tableExists(connection, metadata, tableName)) {
                    presentTables.add(tableName);
                }
            }
        }
        return schemaInstallStateForMarkers(presentTables);
    }

    private boolean tableExists(Connection connection, DatabaseMetaData metadata, String tableName) throws SQLException {
        return tableExists(connection, metadata, tableName, tableName)
                || tableExists(connection, metadata, tableName, tableName.toUpperCase());
    }

    private boolean tableExists(Connection connection, DatabaseMetaData metadata, String markerName, String lookupName)
            throws SQLException {
        try (ResultSet resultSet = metadata.getTables(connection.getCatalog(), null, lookupName, new String[]{"TABLE"})) {
            while (resultSet.next()) {
                String resolvedName = resultSet.getString("TABLE_NAME");
                if (markerName.equalsIgnoreCase(resolvedName)) {
                    return true;
                }
            }
        }
        return false;
    }

    static SchemaInstallState schemaInstallStateForMarkers(Set<String> presentTables) {
        if (presentTables == null || presentTables.isEmpty()) {
            return SchemaInstallState.ABSENT;
        }
        return presentTables.size() == SCHEMA_MARKER_TABLES.length
                ? SchemaInstallState.COMPLETE
                : SchemaInstallState.PARTIAL;
    }

    enum SchemaInstallState {
        ABSENT,
        COMPLETE,
        PARTIAL
    }

    enum PqaOfficialSeedState {
        ABSENT,
        COMPLETE,
        PARTIAL
    }
}
