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
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

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
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, CoreDataAutoConfiguration.class})
@ConditionalOnClass(DataSource.class)
@ConditionalOnBean(value = PlatformConfig.class, name = "contexaDataSource")
@ConditionalOnProperty(prefix = "contexa.iam.seed", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamSeedDataAutoConfiguration {

    private static final char BYTE_ORDER_MARK = (char) 0xFEFF;

    private static final String CANONICAL_SCHEMA_LOCATION = "META-INF/contexa/db/schema.sql";
    static final String IAM_SEED_DATA_INITIALIZER_BEAN = "contexaIamSeedDataInitializer";
    static final String CONTEXA_ENTITY_MANAGER_FACTORY_BEAN = "contexaEntityManagerFactory";
    private static final int EXPECTED_OFFICIAL_METRIC_EVALUATION_CONTRACTS = 66;
    private static final int EXPECTED_OFFICIAL_PROMPT_SIGNAL_CONTRACTS = 688;
    private static final int EXPECTED_OFFICIAL_METRIC_PURPOSE_CONTRACTS = 12;
    private static final int EXPECTED_OFFICIAL_METRIC_INPUT_CONTRACTS = 396;
    private static final int EXPECTED_OFFICIAL_METRIC_CHECK_DISPLAY_EVIDENCE_CONTRACTS = 66;
    private static final int EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_CONTRACTS = 390;
    private static final int EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_BINDINGS = 212;

    static final String[] SCHEMA_LOCATIONS = {
            CANONICAL_SCHEMA_LOCATION
    };

    static final String[] SCHEMA_MARKER_TABLES = {
            "ctxa_users",
            "ctxa_admin_menu",
            "ctxa_sealed_evidence_package",
            "ctxa_official_metric_evaluation_contract",
            "ctxa_official_prompt_signal_contract",
            "ctxa_verification_run_ledger",
            "ctxa_official_verification_run_batch",
            "ctxa_official_verification_metric_snapshot",
            "ctxa_official_metric_purpose_contract",
            "ctxa_official_metric_purpose_evidence_ledger",
            "ctxa_official_actual_prompt_problem_ledger",
            "ctxa_official_verification_prompt_comparison",
            "ctxa_pqa_sealed_evidence_resource_status",
            "ctxa_ai_security_decision_observation"
    };

    private static final String VECTOR_DIMENSIONS_PROPERTY = "contexa.vectorstore.pgvector.dimensions";
    private static final int SCHEMA_VECTOR_DIMENSIONS = 1024;
    private static final int HNSW_MAX_DIMENSIONS = 2000;
    private static final Pattern VECTOR_INDEX =
            Pattern.compile("(?is)create\\s+index\\s+\\S+\\s+on\\s+ctxa_vector_store\\s+using\\s+hnsw[^;]*;");

    static final String[] SEED_LOCATIONS = {
            "META-INF/contexa/db/data.sql",
            "META-INF/contexa/db/data-menu.sql",
            "META-INF/contexa/db/data-system-settings.sql"
    };

    /**
     * The sample accounts (one shared password), so that a first start can be signed in to without any setting. They are
     * added to a database without user accounts only: their group rows name the user ids 1 to 5, which on a database in
     * use belong to other people. {@code contexa.iam.seed.accounts.enabled=false} leaves them out.
     */
    static final String ACCOUNT_SEED_LOCATION = "META-INF/contexa/db/data-accounts.sql";
    static final String ACCOUNT_SEED_PROPERTY = "contexa.iam.seed.accounts.enabled";

    /**
     * One administrator whose password comes from the configuration (contexa init keeps it outside the
     * project), so an application whose sign-in Contexa provides can be signed in to without the shared-password
     * sample accounts. Nothing happens without the password.
     */
    static final String ADMIN_PASSWORD_PROPERTY = "contexa.iam.seed.admin.password";
    static final String ADMIN_USERNAME_PROPERTY = "contexa.iam.seed.admin.username";
    static final String ADMIN_EMAIL_PROPERTY = "contexa.iam.seed.admin.email";
    static final String DEFAULT_ADMIN_USERNAME = "admin";
    static final String DEFAULT_ADMIN_EMAIL = "admin@localhost";
    /** The system administrators group of META-INF/contexa/db/data.sql, which holds ROLE_ADMIN. */
    static final long ADMIN_GROUP_ID = 1L;

    private static final Pattern CREATE_TABLE_IF_NOT_EXISTS =
            Pattern.compile("^create table if not exists ([\\w.\"]+)");
    private static final Pattern CREATE_INDEX_IF_NOT_EXISTS =
            Pattern.compile("^create (?:unique )?index if not exists \\S+ on (?:only )?([\\w.\"]+)");
    /** The columns the schema adds to a table after its {@code create table}; the same statements the maintenance replays. */
    private static final Pattern ALTER_TABLE_ADD_COLUMN_IF_NOT_EXISTS =
            Pattern.compile("^alter table (?:if exists )?(?:only )?([\\w.\"]+) .*\\badd column if not exists\\b.*");

    /**
     * The seed files the initializer runs, in order; the sample accounts last. Without the property they come unless an
     * administrator password is configured: that administrator is the account the configuration asked for, and the sample
     * administrator of the same name would take its place.
     */
    static List<String> seedLocations(Environment environment) {
        List<String> locations = new ArrayList<>(List.of(SEED_LOCATIONS));
        Boolean asked = environment.getProperty(ACCOUNT_SEED_PROPERTY, Boolean.class);
        String adminPassword = environment.getProperty(ADMIN_PASSWORD_PROPERTY);
        if (asked != null ? asked : adminPassword == null || adminPassword.isBlank()) {
            locations.add(ACCOUNT_SEED_LOCATION);
        }
        return List.copyOf(locations);
    }

    @Bean(name = "contexaIamSeedDataJpaDependencyConfigurer")
    public static BeanFactoryPostProcessor iamSeedDataJpaDependencyConfigurer() {
        return beanFactory -> {
            if (!beanFactory.containsBeanDefinition(CONTEXA_ENTITY_MANAGER_FACTORY_BEAN)
                    || !beanFactory.containsBeanDefinition(IAM_SEED_DATA_INITIALIZER_BEAN)) {
                return;
            }
            BeanDefinition entityManagerFactory =
                    beanFactory.getBeanDefinition(CONTEXA_ENTITY_MANAGER_FACTORY_BEAN);
            Set<String> dependsOn = new LinkedHashSet<>();
            if (entityManagerFactory.getDependsOn() != null) {
                for (String dependency : entityManagerFactory.getDependsOn()) {
                    dependsOn.add(dependency);
                }
            }
            if (dependsOn.add(IAM_SEED_DATA_INITIALIZER_BEAN)) {
                entityManagerFactory.setDependsOn(dependsOn.toArray(String[]::new));
                log.info("[IamSeedData] contexaEntityManagerFactory will wait for IAM schema maintenance");
            }
        };
    }

    @Bean(name = IAM_SEED_DATA_INITIALIZER_BEAN)
    public InitializingBean iamSeedDataInitializer(
            @Qualifier("contexaDataSource") DataSource dataSource,
            OssSchemaGovernance contexaOssSchemaGovernance,
            OssSchemaMaintenanceBacklog maintenanceBacklog,
            Environment environment) {
        return () -> {
            boolean enterpriseManaged = contexaOssSchemaGovernance.hasProvenance(OssSchemaGovernance.ENTERPRISE_OWNER);
            boolean ossProvenanceExists = contexaOssSchemaGovernance.hasProvenance(OssSchemaGovernance.OSS_OWNER);
            boolean enterpriseRequested = environment.getProperty(
                    "contexa.enterprise.enabled", Boolean.class, false);
            ContexaSchemaInventory.DatabaseObjects preInstallationObjects =
                    ContexaSchemaInventory.readDatabase(dataSource);
            SchemaInstallState schemaInstallState = detectSchemaInstallState(dataSource);
            if (shouldRejectUnverifiedEnterpriseSchema(
                    enterpriseRequested, ossProvenanceExists, schemaInstallState, preInstallationObjects)) {
                throw new IllegalStateException(
                        "Enterprise schema coordination rejected a non-empty database without verified OSS "
                                + "provenance. No schema changes were applied.");
            }
            if (schemaInstallState == SchemaInstallState.ABSENT) {
                contexaOssSchemaGovernance.assertNoOssOwnershipCollisions(preInstallationObjects);
            }
            initializeSchemaAndSeedData(dataSource, schemaInstallState, enterpriseManaged,
                    enterpriseRequested ? maintenanceBacklog : null, seedLocations(environment),
                        environment.getProperty(VECTOR_DIMENSIONS_PROPERTY, Integer.class, SCHEMA_VECTOR_DIMENSIONS));
            OssSchemaGovernance.GovernanceReport report = contexaOssSchemaGovernance.initializeAndRecordOss(
                    schemaInstallState == SchemaInstallState.ABSENT ? preInstallationObjects : null);
            log.info("[IamSeedData] OSS schema provenance verified. version={}, tables={}, views={}, checksum={}, "
                            + "hostTables={}, hostViews={}, unownedTables={}, unownedViews={}",
                    report.inventory().version(), report.inventory().tables().size(),
                    report.inventory().views().size(), report.inventory().checksum(),
                    report.ownership().host().tables().size(), report.ownership().host().views().size(),
                    report.ownership().unowned().tables().size(), report.ownership().unowned().views().size());
        };
    }

    /**
     * The administrator of contexa.iam.seed.admin.password, created once every singleton exists: Contexa's JPA is
     * ready then (the users and their groups are JPA tables) and the web server has not started yet.
     */
    @Bean(name = "contexaIamAdministratorSeed")
    public SmartInitializingSingleton iamAdministratorSeed(
            ObjectProvider<UserRepository> users,
            ObjectProvider<GroupRepository> groups,
            @Qualifier("contexaTransactionManager") ObjectProvider<PlatformTransactionManager> transactions,
            Environment environment) {
        return () -> {
            UserRepository userRepository = users.getIfAvailable();
            GroupRepository groupRepository = groups.getIfAvailable();
            PlatformTransactionManager transactionManager = transactions.getIfAvailable();
            if (userRepository == null || groupRepository == null || transactionManager == null) {
                if (StringUtils.hasText(environment.getProperty(ADMIN_PASSWORD_PROPERTY))) {
                    log.warn("[IamSeedData] The administrator from {} is not created: Contexa's user repositories are not "
                            + "available", ADMIN_PASSWORD_PROPERTY);
                }
                return;
            }
            seedAdministrator(new JpaAdministratorAccounts(userRepository, groupRepository,
                    new TransactionTemplate(transactionManager)), environment);
        };
    }

    @Bean(name = "contexaOssSchemaGovernance")
    public OssSchemaGovernance ossSchemaGovernance(
            @Qualifier("contexaDataSource") DataSource dataSource) {
        return new OssSchemaGovernance(dataSource);
    }

    @Bean(name = "contexaOssSchemaMaintenanceBacklog")
    public OssSchemaMaintenanceBacklog ossSchemaMaintenanceBacklog(
            @Qualifier("contexaDataSource") DataSource dataSource) {
        return new OssSchemaMaintenanceBacklog(dataSource);
    }

    /**
     * Runs after every singleton exists, which is after the enterprise Flyway migrations. Nothing is left over when
     * the schema needed no put-off statement; a statement that still fails stops the start.
     */
    @Bean(name = "contexaOssSchemaMaintenanceBacklogCompletion")
    public static SmartInitializingSingleton ossSchemaMaintenanceBacklogCompletion(
            OssSchemaMaintenanceBacklog maintenanceBacklog) {
        return maintenanceBacklog::complete;
    }

    private void initializeSchemaAndSeedData(
            DataSource dataSource,
            SchemaInstallState schemaInstallState,
            boolean enterpriseManaged,
            OssSchemaMaintenanceBacklog deferTo,
            List<String> seedLocations,
            int vectorDimensions)
            throws SQLException, IOException {
        if (schemaInstallState == SchemaInstallState.PARTIAL) {
            throw new IllegalStateException(
                    "Contexa schema is partially installed without a complete ownership contract. "
                            + "No schema changes were applied. Restore a verified OSS backup or use a clean database.");
        }
        if (schemaInstallState == SchemaInstallState.ABSENT) {
            for (String location : SCHEMA_LOCATIONS) {
                Resource schema = ContexaResources.sql(location);
                if (!schema.exists()) {
                    log.warn("[IamSeedData] classpath:{} not found, skipping schema initialization", location);
                    continue;
                }
                String sql = sanitizeSchemaSqlForInstalledDatabase(
                        sizeVectorTable(schema.getContentAsString(StandardCharsets.UTF_8), vectorDimensions));
                executeSchemaSql(dataSource, location, sql);
                log.info("[IamSeedData] {} executed", location);
            }
            SchemaInstallState completedState = detectSchemaInstallState(dataSource);
            if (completedState != SchemaInstallState.COMPLETE) {
                throw new IllegalStateException(
                        "Contexa schema is partially installed after canonical schema execution. "
                                + "Rebuild the Contexa database or run the canonical "
                                + "META-INF/contexa/db/schema.sql manually before starting the application.");
            }
        } else if (schemaInstallState == SchemaInstallState.COMPLETE) {
            log.info("[IamSeedData] Contexa schema already installed, skipping schema initialization");
            if (shouldApplyCanonicalSchemaMaintenance(schemaInstallState, enterpriseManaged)) {
                applyCanonicalSchemaMaintenance(dataSource, deferTo, deferTo != null);
            } else {
                log.info("[IamSeedData] Enterprise provenance is present; OSS canonical DDL maintenance is skipped");
                createMissingOssTables(dataSource);
            }
        }
        for (String location : seedLocations) {
            if (ACCOUNT_SEED_LOCATION.equals(location) && hasUserAccounts(dataSource)) {
                log.info("[IamSeedData] User accounts exist, so the sample accounts of {} are not added", location);
                continue;
            }
            Resource seed = ContexaResources.sql(location);
            if (!seed.exists()) {
                log.warn("[IamSeedData] classpath:{} not found, skipping", location);
                continue;
            }
            seedPopulator(seed).execute(dataSource);
            log.info("[IamSeedData] {} executed", location);
            if (ACCOUNT_SEED_LOCATION.equals(location)) {
                log.warn("[IamSeedData] Sample accounts were added because no user account existed: admin (administrator), "
                        + "manager, developer, user and finance, all with the password 1111. Sign in to the console at "
                        + "/contexa/admin/login and change the password with \"Change password\" in the console header.");
            }
        }
        completePqaOfficialSchemaIfNeeded(dataSource);
    }

    private static boolean hasUserAccounts(DataSource dataSource) {
        Integer accounts = new JdbcTemplate(dataSource).queryForObject("select count(*) from ctxa_users", Integer.class);
        return accounts != null && accounts > 0;
    }

    /**
     * The seed scripts are UTF-8, like the schema. Without the explicit encoding Java 17 reads them with the
     * operating system's charset: Korean names are stored garbled on Korean Windows (MS949), and under a POSIX
     * locale different names turn into the same '?' text and the startup fails on a unique constraint.
     */
    static ResourceDatabasePopulator seedPopulator(Resource seed) {
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.setContinueOnError(false);
        populator.setSqlScriptEncoding(StandardCharsets.UTF_8.name());
        populator.addScript(seed);
        return populator;
    }

    /**
     * Creates the configured administrator once. An existing user with that username or e-mail is never changed, so a
     * password changed in the admin console is not reset at the next start. The password is stored in the {@code {bcrypt}}
     * form of Spring's delegating encoder, like the sample accounts. The account signs in with two steps, like the sample
     * administrator, and its e-mail receives the one-time code.
     */
    static AdministratorSeed seedAdministrator(AdministratorAccounts accounts, Environment environment) {
        String password = environment.getProperty(ADMIN_PASSWORD_PROPERTY);
        if (password == null || password.isBlank()) {
            return AdministratorSeed.NOT_REQUESTED;
        }
        String username = environment.getProperty(ADMIN_USERNAME_PROPERTY, DEFAULT_ADMIN_USERNAME).trim();
        String email = environment.getProperty(ADMIN_EMAIL_PROPERTY, DEFAULT_ADMIN_EMAIL).trim();
        if (accounts.exists(username, email)) {
            log.info("[IamSeedData] A user named '{}' or with the e-mail {} exists; the administrator from {} is not created",
                    username, email, ADMIN_PASSWORD_PROPERTY);
            return AdministratorSeed.ALREADY_PRESENT;
        }
        String encoded = PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(password);
        long userId = accounts.create(username, email, encoded, "Administrator");
        if (accounts.groupExists(ADMIN_GROUP_ID)) {
            accounts.join(userId, ADMIN_GROUP_ID);
            log.info("[IamSeedData] Administrator '{}' created from {}", username, ADMIN_PASSWORD_PROPERTY);
        } else {
            log.warn("[IamSeedData] Administrator '{}' created from {}, but the administrators group {} is missing; "
                    + "assign a group in the admin console", username, ADMIN_PASSWORD_PROPERTY, ADMIN_GROUP_ID);
        }
        return AdministratorSeed.CREATED;
    }

    enum AdministratorSeed {
        NOT_REQUESTED,
        CREATED,
        ALREADY_PRESENT
    }

    static boolean shouldApplyCanonicalSchemaMaintenance(
            SchemaInstallState schemaInstallState,
            boolean enterpriseManaged) {
        return schemaInstallState == SchemaInstallState.COMPLETE && !enterpriseManaged;
    }

    static boolean shouldRejectUnverifiedEnterpriseSchema(
            boolean enterpriseRequested,
            boolean ossProvenanceExists,
            SchemaInstallState schemaInstallState,
            ContexaSchemaInventory.DatabaseObjects preInstallationObjects) {
        return enterpriseRequested
                && !ossProvenanceExists
                && schemaInstallState == SchemaInstallState.ABSENT
                && (!preInstallationObjects.tables().isEmpty() || !preInstallationObjects.views().isEmpty());
    }

    /**
     * @param deferTo where a statement goes that names a column or table only the enterprise migrations add; used
     *                only when {@code deferMissingObjects} is set, which an enterprise start sets. Without it every
     *                failure stops the start.
     */
    static void applyCanonicalSchemaMaintenance(
            DataSource dataSource, OssSchemaMaintenanceBacklog deferTo, boolean deferMissingObjects)
            throws IOException, SQLException {
        Resource schema = ContexaResources.sql(CANONICAL_SCHEMA_LOCATION);
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
        if (deferMissingObjects) {
            List<String> deferred = executeSchemaSqlDeferring(
                    dataSource, CANONICAL_SCHEMA_LOCATION + "#maintenance", maintenanceSql);
            deferTo.defer(deferred);
            log.info("[IamSeedData] {} idempotent schema maintenance executed; {} statement(s) wait for the enterprise "
                    + "migrations", CANONICAL_SCHEMA_LOCATION, deferred.size());
            return;
        }
        executeSchemaSql(dataSource, CANONICAL_SCHEMA_LOCATION + "#maintenance", maintenanceSql);
        log.info("[IamSeedData] {} idempotent schema maintenance executed", CANONICAL_SCHEMA_LOCATION);
    }

    /**
     * A1-6: an OSS table added after an enterprise took over the schema has no other way in. The enterprise migrations
     * run after this initializer, and the OSS inventory must be complete before them, so the tables the database lacks
     * are created here with their indexes. Tables that exist are left alone: their evolution stays the enterprise's.
     */
    static void createMissingOssTables(DataSource dataSource) throws IOException, SQLException {
        Resource schema = ContexaResources.sql(CANONICAL_SCHEMA_LOCATION);
        if (!schema.exists()) {
            return;
        }
        ContexaSchemaInventory.Snapshot inventory = ContexaSchemaInventory.fromResources(
                OssSchemaGovernance.OSS_OWNER, List.of(schema));
        Set<String> missingTables = ContexaSchemaInventory.diff(
                inventory, ContexaSchemaInventory.readDatabase(dataSource)).missingTables();
        if (missingTables.isEmpty()) {
            return;
        }
        String creationSql = extractMissingTableCreationSql(
                sanitizeSchemaSqlForInstalledDatabase(schema.getContentAsString(StandardCharsets.UTF_8)), missingTables);
        if (creationSql.isBlank()) {
            return;
        }
        executeSchemaSql(dataSource, CANONICAL_SCHEMA_LOCATION + "#missing-tables", creationSql);
        log.info("[IamSeedData] OSS tables missing from the enterprise-managed database were created: {}", missingTables);
    }

    /**
     * The {@code create table if not exists}, {@code add column if not exists} and {@code create index if not exists}
     * statements of the given tables, in the order of the schema. A column that the schema adds to a table with
     * {@code alter table} is not in its {@code create table}, so a table created here would lack it.
     */
    static String extractMissingTableCreationSql(String sql, Set<String> missingTables) {
        if (sql == null || sql.isBlank() || missingTables == null || missingTables.isEmpty()) {
            return "";
        }
        Set<String> missing = new LinkedHashSet<>();
        for (String table : missingTables) {
            missing.add(table.toLowerCase(Locale.ROOT));
        }
        StringBuilder creation = new StringBuilder();
        for (String statement : splitSqlStatements(sql)) {
            String candidate = statement.trim();
            String normalized = normalizeSqlStatement(candidate);
            String table = matchedTable(CREATE_TABLE_IF_NOT_EXISTS, normalized);
            if (table == null) {
                table = matchedTable(CREATE_INDEX_IF_NOT_EXISTS, normalized);
            }
            if (table == null) {
                table = matchedTable(ALTER_TABLE_ADD_COLUMN_IF_NOT_EXISTS, normalized);
            }
            if (table != null && missing.contains(table)) {
                creation.append(candidate).append(";\n");
            }
        }
        return creation.toString();
    }

    private static String matchedTable(Pattern pattern, String normalizedStatement) {
        Matcher matcher = pattern.matcher(normalizedStatement);
        if (!matcher.find()) {
            return null;
        }
        String name = matcher.group(1).replace("\"", "");
        int schemaSeparator = name.lastIndexOf('.');
        return schemaSeparator >= 0 ? name.substring(schemaSeparator + 1) : name;
    }

    private static String normalizeSqlStatement(String sqlStatement) {
        return sqlStatement
                .replaceAll("(?s)/\\*.*?\\*/", " ")
                .replaceAll("(?m)--.*$", " ")
                .replaceAll("\\s+", " ")
                .trim()
                .toLowerCase(Locale.ROOT);
    }

    private void completePqaOfficialSchemaIfNeeded(DataSource dataSource) throws SQLException, IOException {
        PqaOfficialSeedState seedState = detectPqaOfficialSeedState(dataSource);
        if (seedState == PqaOfficialSeedState.ABSENT) {
            Resource schema = ContexaResources.sql(CANONICAL_SCHEMA_LOCATION);
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
            log.info("[IamSeedData] PQA official contract catalog seed is {}; attempting catalog completion",
                    seedState);
            completePqaOfficialContractCatalog(dataSource);
            seedState = detectPqaOfficialSeedState(dataSource);
        }
        if (seedState != PqaOfficialSeedState.COMPLETE) {
            throw new IllegalStateException(
                    "PQA official schema seed is incomplete after canonical META-INF/contexa/db/schema.sql execution. "
                            + "Rebuild the Contexa database or run the canonical "
                            + "META-INF/contexa/db/schema.sql manually before starting the application.");
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
            if (!tableExists(connection, metadata, "ctxa_official_metric_purpose_contract")
                    || !tableExists(connection, metadata, "ctxa_official_metric_evaluation_contract")
                    || !tableExists(connection, metadata, "ctxa_official_metric_customer_display_contract")
                    || !tableExists(connection, metadata, "ctxa_official_metric_customer_display_binding")
                    || !tableExists(connection, metadata, "ctxa_official_metric_input_contract")
                    || !tableExists(connection, metadata, "ctxa_official_metric_check_display_evidence_contract")
                    || !tableExists(connection, metadata, "ctxa_official_prompt_signal_contract")
                    || !tableExists(connection, metadata, "ctxa_official_verification_metric_definition")
                    || !tableExists(connection, metadata, "ctxa_official_verification_metric_check_definition")) {
                return PqaOfficialSeedState.ABSENT;
            }
            return countRows(connection, "ctxa_official_metric_evaluation_contract")
                    >= EXPECTED_OFFICIAL_METRIC_EVALUATION_CONTRACTS
                    && countRows(connection, "ctxa_official_prompt_signal_contract")
                    >= EXPECTED_OFFICIAL_PROMPT_SIGNAL_CONTRACTS
                    && countRows(connection, "ctxa_official_metric_purpose_contract")
                    >= EXPECTED_OFFICIAL_METRIC_PURPOSE_CONTRACTS
                    && countRows(connection, "ctxa_official_metric_input_contract")
                    >= EXPECTED_OFFICIAL_METRIC_INPUT_CONTRACTS
                    && countRows(connection, "ctxa_official_metric_check_display_evidence_contract")
                    >= EXPECTED_OFFICIAL_METRIC_CHECK_DISPLAY_EVIDENCE_CONTRACTS
                    && countRows(connection, "ctxa_official_metric_customer_display_contract")
                    >= EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_CONTRACTS
                    && countRows(connection, "ctxa_official_metric_customer_display_binding")
                    >= EXPECTED_OFFICIAL_METRIC_CUSTOMER_DISPLAY_BINDINGS
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

    static void executeSchemaSql(DataSource dataSource, String location, String sql) throws SQLException {
        executeStatements(dataSource, location, sql, null);
    }

    /**
     * Like {@link #executeSchemaSql}, but a statement that fails because a column or table does not exist yet is
     * returned instead of stopping the script; every other failure still stops it.
     */
    static List<String> executeSchemaSqlDeferring(DataSource dataSource, String location, String sql)
            throws SQLException {
        List<String> deferred = new ArrayList<>();
        executeStatements(dataSource, location, sql, deferred);
        return deferred;
    }

    /** PostgreSQL {@code undefined_column} and {@code undefined_table}. */
    static boolean isMissingObjectFailure(SQLException error) {
        return "42703".equals(error.getSQLState()) || "42P01".equals(error.getSQLState());
    }

    private static void executeStatements(
            DataSource dataSource, String location, String sql, List<String> deferred) throws SQLException {
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
                    if (deferred != null && isMissingObjectFailure(ex)) {
                        log.warn("[IamSeedData] Statement #{} of {} waits for the enterprise migrations ({}): {}",
                                statementNumber, location, ex.getMessage(), abbreviate(sqlStatement));
                        deferred.add(sqlStatement);
                        continue;
                    }
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

    private static String abbreviate(String sqlStatement) {
        String singleLine = sqlStatement.replaceAll("\\s+", " ").trim();
        return singleLine.length() <= 500 ? singleLine : singleLine.substring(0, 500) + "...";
    }

    /**
     * The vector table is made for the embedding model in use, which is the application's choice: vectors of another size cannot
     * be stored. pgvector's HNSW index stops at 2000 dimensions, and the vector store says what to do about that at start.
     */
    static String sizeVectorTable(String sql, int dimensions) {
        String sized = sql.replace("embedding vector(" + SCHEMA_VECTOR_DIMENSIONS + ")", "embedding vector(" + dimensions + ")");
        return dimensions > HNSW_MAX_DIMENSIONS ? VECTOR_INDEX.matcher(sized).replaceAll("") : sized;
    }

    static String sanitizeSchemaSqlForInstalledDatabase(String sql) {
        if (sql == null || sql.isBlank()) {
            return "";
        }
        String normalized = !sql.isEmpty() && sql.charAt(0) == BYTE_ORDER_MARK ? sql.substring(1) : sql;
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
                .toLowerCase(Locale.ROOT);
        // Under ALTER COLUMN only the removal of a NOT NULL constraint or of a default is replayed;
        // both are no-ops once applied. Type, default and constraint changes are never replayed.
        return normalized.matches("^alter table \\S+ .*\\badd column if not exists\\b.*")
                || normalized.matches("^alter table \\S+ alter column \\S+ drop (not null|default)$")
                || normalized.matches("^create table if not exists\\b.*")
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
                || tableExists(connection, metadata, tableName, tableName.toUpperCase(Locale.ROOT));
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
