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
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogWriter;
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
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Slf4j
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, CoreDataAutoConfiguration.class})
@ConditionalOnClass(DataSource.class)
@ConditionalOnBean(value = PlatformConfig.class, name = "contexaDataSource")
@ConditionalOnProperty(prefix = "contexa.iam.seed", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamSeedDataAutoConfiguration {

    private static final String CANONICAL_SCHEMA_LOCATION = "db/schema.sql";
    private static final int EXPECTED_OFFICIAL_METRIC_EVALUATION_CONTRACTS = 66;
    private static final int EXPECTED_OFFICIAL_PROMPT_SIGNAL_CONTRACTS = 688;
    private static final int EXPECTED_OFFICIAL_METRIC_PURPOSE_CONTRACTS = 12;
    private static final int EXPECTED_OFFICIAL_METRIC_INPUT_CONTRACTS = 396;
    private static final int EXPECTED_OFFICIAL_METRIC_CHECK_DISPLAY_EVIDENCE_CONTRACTS = 66;
    private static final int EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_CONTRACTS = 390;
    private static final int EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_BINDINGS = 212;
    private static final int EXPECTED_OFFICIAL_VERIFICATION_METRIC_DEFINITIONS = 12;
    private static final int EXPECTED_OFFICIAL_VERIFICATION_METRIC_CHECK_DEFINITIONS = 26;

    static final String[] SCHEMA_LOCATIONS = {
            CANONICAL_SCHEMA_LOCATION
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
            "pqa_sealed_evidence_resource_status",
            "hcad_detection_evaluation"
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
                String sql = sanitizeSchemaSqlForInstalledDatabase(
                        schema.getContentAsString(StandardCharsets.UTF_8));
                executeSchemaSql(dataSource, location, sql);
                log.info("[IamSeedData] {} executed", location);
            }
            SchemaInstallState completedState = detectSchemaInstallState(dataSource);
            if (completedState != SchemaInstallState.COMPLETE) {
                throw new IllegalStateException(
                        "Contexa schema is partially installed after canonical schema execution. "
                                + "Rebuild the Contexa database or run the canonical "
                                + "db/schema.sql manually before starting the application.");
            }
        } else if (schemaInstallState == SchemaInstallState.COMPLETE) {
            log.info("[IamSeedData] Contexa schema already installed, skipping schema initialization");
            applyCanonicalSchemaMaintenance(dataSource);
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

    private void applyCanonicalSchemaMaintenance(DataSource dataSource) throws IOException, SQLException {
        Resource schema = new ClassPathResource(CANONICAL_SCHEMA_LOCATION);
        if (!schema.exists()) {
            log.warn("[IamSeedData] classpath:{} not found, skipping schema maintenance",
                    CANONICAL_SCHEMA_LOCATION);
            return;
        }
        String maintenanceSql = extractIdempotentSchemaMaintenanceSql(
                sanitizeSchemaSqlForInstalledDatabase(schema.getContentAsString(StandardCharsets.UTF_8)));
        if (maintenanceSql.isBlank()) {
            log.info("[IamSeedData] No idempotent schema maintenance statements found");
            return;
        }
        executeSchemaSql(dataSource, CANONICAL_SCHEMA_LOCATION + "#maintenance", maintenanceSql);
        log.info("[IamSeedData] {} idempotent schema maintenance executed", CANONICAL_SCHEMA_LOCATION);
    }

    private void completePqaOfficialSchemaIfNeeded(DataSource dataSource) throws SQLException, IOException {
        PqaOfficialSeedState seedState = detectPqaOfficialSeedState(dataSource);
        if (seedState == PqaOfficialSeedState.ABSENT) {
            Resource schema = new ClassPathResource(CANONICAL_SCHEMA_LOCATION);
            if (!schema.exists()) {
                log.warn("[IamSeedData] classpath:{} not found, cannot complete PQA official schema seed",
                        CANONICAL_SCHEMA_LOCATION);
                return;
            }
            log.warn("[IamSeedData] PQA official schema tables are absent; attempting idempotent schema completion");
            executeSchemaSql(dataSource, CANONICAL_SCHEMA_LOCATION, pqaSeedCompletionSchemaSql(schema));
            log.info("[IamSeedData] {} executed for PQA official schema completion", CANONICAL_SCHEMA_LOCATION);
            seedState = detectPqaOfficialSeedState(dataSource);
        }
        if (seedState != PqaOfficialSeedState.COMPLETE) {
            log.warn("[IamSeedData] PQA official contract catalog seed is {}; attempting catalog completion",
                    seedState);
            completePqaOfficialContractCatalog(dataSource);
            seedState = detectPqaOfficialSeedState(dataSource);
        }
        if (seedState != PqaOfficialSeedState.COMPLETE) {
            throw new IllegalStateException(
                    "PQA official schema seed is incomplete after canonical db/schema.sql execution. "
                            + "Rebuild the Contexa database or run the canonical "
                            + "db/schema.sql manually before starting the application.");
        }
    }

    private void completePqaOfficialContractCatalog(DataSource dataSource) {
        OfficialMetricPurposeContractCatalogWriter writer =
                new OfficialMetricPurposeContractCatalogWriter(new JdbcTemplate(dataSource), new ObjectMapper());
        writer.upsertFullMetricContractCatalog();
        writer.assertFullMetricContractCatalogPersisted();
        log.info("[IamSeedData] PQA official contract catalog completed from runtime catalog resources");
    }

    private String pqaSeedCompletionSchemaSql(Resource schema) throws IOException {
        String sql = schema.getContentAsString(StandardCharsets.UTF_8);
        return sanitizeSchemaSqlForInstalledDatabase(sql)
                .replaceAll("(?is)\\balter\\s+table\\s+\\S+\\s+alter\\s+column\\s+\\S+\\s+set\\s+data\\s+type\\s+[^;]+;\\s*", "");
    }

    private PqaOfficialSeedState detectPqaOfficialSeedState(DataSource dataSource) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            if (!tableExists(connection, metadata, "official_metric_purpose_contract")
                    || !tableExists(connection, metadata, "official_metric_evaluation_contract")
                    || !tableExists(connection, metadata, "official_metric_customer_display_contract")
                    || !tableExists(connection, metadata, "official_metric_customer_display_binding")
                    || !tableExists(connection, metadata, "official_metric_input_contract")
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
                    && countRows(connection, "official_metric_purpose_contract")
                    >= EXPECTED_OFFICIAL_METRIC_PURPOSE_CONTRACTS
                    && countRows(connection, "official_metric_input_contract")
                    >= EXPECTED_OFFICIAL_METRIC_INPUT_CONTRACTS
                    && countRows(connection, "official_metric_check_display_evidence_contract")
                    >= EXPECTED_OFFICIAL_METRIC_CHECK_DISPLAY_EVIDENCE_CONTRACTS
                    && countRows(connection, "official_metric_customer_display_contract")
                    >= EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_CONTRACTS
                    && countRows(connection, "official_metric_customer_display_binding")
                    >= EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_BINDINGS
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

    private void executeSchemaSql(DataSource dataSource, String location, String sql) throws SQLException {
        List<String> statements = splitSqlStatements(sql);
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            int statementNumber = 0;
            for (String candidate : statements) {
                String sqlStatement = candidate.trim();
                if (isSqlStatementBlank(sqlStatement)) {
                    continue;
                }
                statementNumber++;
                try {
                    statement.execute(sqlStatement);
                } catch (SQLException ex) {
                    throw new SQLException(
                            "Failed to execute SQL script statement #" + statementNumber + " of " + location
                                    + ": " + abbreviate(sqlStatement),
                            ex);
                }
            }
        }
    }

    static List<String> splitSqlStatements(String sql) {
        List<String> statements = new ArrayList<>();
        if (sql == null || sql.isBlank()) {
            return statements;
        }
        StringBuilder current = new StringBuilder();
        boolean singleQuoted = false;
        boolean doubleQuoted = false;
        boolean lineComment = false;
        boolean blockComment = false;
        String dollarQuote = null;
        for (int i = 0; i < sql.length(); i++) {
            char ch = sql.charAt(i);
            char next = i + 1 < sql.length() ? sql.charAt(i + 1) : '\0';

            if (lineComment) {
                current.append(ch);
                if (ch == '\n' || ch == '\r') {
                    lineComment = false;
                }
                continue;
            }
            if (blockComment) {
                current.append(ch);
                if (ch == '*' && next == '/') {
                    current.append(next);
                    i++;
                    blockComment = false;
                }
                continue;
            }
            if (dollarQuote != null) {
                if (sql.startsWith(dollarQuote, i)) {
                    current.append(dollarQuote);
                    i += dollarQuote.length() - 1;
                    dollarQuote = null;
                } else {
                    current.append(ch);
                }
                continue;
            }
            if (singleQuoted) {
                current.append(ch);
                if (ch == '\'' && next == '\'') {
                    current.append(next);
                    i++;
                } else if (ch == '\'') {
                    singleQuoted = false;
                }
                continue;
            }
            if (doubleQuoted) {
                current.append(ch);
                if (ch == '"' && next == '"') {
                    current.append(next);
                    i++;
                } else if (ch == '"') {
                    doubleQuoted = false;
                }
                continue;
            }

            if (ch == '-' && next == '-') {
                current.append(ch).append(next);
                i++;
                lineComment = true;
                continue;
            }
            if (ch == '/' && next == '*') {
                current.append(ch).append(next);
                i++;
                blockComment = true;
                continue;
            }
            if (ch == '\'') {
                current.append(ch);
                singleQuoted = true;
                continue;
            }
            if (ch == '"') {
                current.append(ch);
                doubleQuoted = true;
                continue;
            }
            if (ch == '$') {
                String quoteTag = readDollarQuoteTag(sql, i);
                if (quoteTag != null) {
                    current.append(quoteTag);
                    i += quoteTag.length() - 1;
                    dollarQuote = quoteTag;
                    continue;
                }
            }
            if (ch == ';') {
                addStatementIfNotBlank(statements, current.toString());
                current.setLength(0);
                continue;
            }
            current.append(ch);
        }
        if (!current.isEmpty()) {
            addStatementIfNotBlank(statements, current.toString());
        }
        return statements;
    }

    private static void addStatementIfNotBlank(List<String> statements, String sqlStatement) {
        if (!isSqlStatementBlank(sqlStatement)) {
            statements.add(sqlStatement);
        }
    }

    private static String readDollarQuoteTag(String sql, int offset) {
        int end = sql.indexOf('$', offset + 1);
        if (end < 0) {
            return null;
        }
        for (int i = offset + 1; i < end; i++) {
            char ch = sql.charAt(i);
            if (!Character.isLetterOrDigit(ch) && ch != '_') {
                return null;
            }
        }
        return sql.substring(offset, end + 1);
    }

    private static boolean isSqlStatementBlank(String sqlStatement) {
        return sqlStatement
                .replaceAll("(?s)/\\*.*?\\*/", "")
                .replaceAll("(?m)--.*$", "")
                .trim()
                .isEmpty();
    }

    private String abbreviate(String sqlStatement) {
        String singleLine = sqlStatement.replaceAll("\\s+", " ").trim();
        return singleLine.length() <= 500 ? singleLine : singleLine.substring(0, 500) + "...";
    }

    static String sanitizeSchemaSqlForInstalledDatabase(String sql) {
        if (sql == null || sql.isBlank()) {
            return "";
        }
        String normalized = sql.startsWith("\uFEFF") ? sql.substring(1) : sql;
        return normalized
                .replaceAll("(?is)\\balter\\s+(table|sequence|view|materialized\\s+view|index)\\s+[^;]+?\\s+owner\\s+to\\s+[^;]+;\\s*", "")
                .replaceAll("(?im)^\\s*create\\s+table\\s+(?!if\\s+not\\s+exists\\b)", "create table if not exists ")
                .replaceAll("(?im)^\\s*create\\s+sequence\\s+(?!if\\s+not\\s+exists\\b)", "create sequence if not exists ")
                .replaceAll("(?im)^\\s*create\\s+(unique\\s+)?index\\s+(?!if\\s+not\\s+exists\\b)", "create $1index if not exists ");
    }

    static String extractIdempotentSchemaMaintenanceSql(String sql) {
        if (sql == null || sql.isBlank()) {
            return "";
        }
        List<String> statements = splitSqlStatements(sql);
        StringBuilder maintenance = new StringBuilder();
        for (String statement : statements) {
            String candidate = statement.trim();
            if (isIdempotentSchemaMaintenanceStatement(candidate)) {
                maintenance.append(candidate).append(";\n");
            }
        }
        return maintenance.toString();
    }

    private static boolean isIdempotentSchemaMaintenanceStatement(String sqlStatement) {
        if (sqlStatement == null || sqlStatement.isBlank()) {
            return false;
        }
        String normalized = sqlStatement
                .replaceAll("(?s)/\\*.*?\\*/", " ")
                .replaceAll("(?m)--.*$", " ")
                .replaceAll("\\s+", " ")
                .trim()
                .toLowerCase();
        return normalized.matches("^alter table \\S+ .*\\badd column if not exists\\b.*")
                || normalized.matches("^create (unique )?index if not exists\\b.*")
                || normalized.matches("^create extension if not exists\\b.*");
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
