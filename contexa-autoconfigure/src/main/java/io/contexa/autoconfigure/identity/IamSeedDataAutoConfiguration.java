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
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
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
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
@AutoConfiguration(after = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class, CoreDataAutoConfiguration.class})
@ConditionalOnClass(DataSource.class)
@ConditionalOnBean(value = PlatformConfig.class, name = "contexaDataSource")
@ConditionalOnProperty(prefix = "contexa.iam.seed", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamSeedDataAutoConfiguration {

    static final String[] SCHEMA_LOCATIONS = {
            "db/schema.sql"
    };

    static final String[] SCHEMA_MARKER_TABLES = {
            "users",
            "admin_menu",
            "sealed_evidence_package",
            "official_metric_evaluation_contract",
            "official_prompt_signal_contract",
            "official_verification_oss_run"
    };

    static final String[] SEED_LOCATIONS = {
            "db/data.sql",
            "db/data-menu.sql",
            "db/data-system-settings.sql"
    };

    @Bean
    @Order(10)
    public ApplicationRunner iamSeedDataRunner(@Qualifier("contexaDataSource") DataSource dataSource) {
        return (ApplicationArguments args) -> {
            SchemaInstallState schemaInstallState = detectSchemaInstallState(dataSource);
            if (schemaInstallState == SchemaInstallState.ABSENT) {
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
            } else if (schemaInstallState == SchemaInstallState.COMPLETE) {
                log.info("[IamSeedData] Contexa schema already installed, skipping schema initialization");
            } else {
                throw new IllegalStateException(
                        "Contexa schema is partially installed. Rebuild the Contexa database with contexa-cli initdb "
                                + "or run the canonical db/schema.sql manually before starting the application.");
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
        };
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
        return sql.replaceAll("(?is)\\balter\\s+(table|sequence|view|materialized\\s+view|index)\\s+[^;]+?\\s+owner\\s+to\\s+[^;]+;\\s*", "");
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
}
