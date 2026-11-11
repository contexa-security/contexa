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
package io.contexa.contexaiam.agent;

import io.contexa.contexacore.autonomous.agent.AbstractActiveAgentListContractTest;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The list of the approved agents in memory follows the database registry as it follows the in-memory one. It runs only
 * against the isolated database named by {@code CONTEXA_TEST_DB_URL}, in a schema of its own that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class JdbcActiveAgentListContractTest extends AbstractActiveAgentListContractTest {

    private static final String SCHEMA = "active_agent_list_test";

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;

    @Override
    protected AgentRegistry newRegistry() {
        try {
            dataSource = new SingleConnectionDataSource(DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"),
                    System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD")), true);
            jdbc = new JdbcTemplate(dataSource);
            jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
            jdbc.execute("create schema " + SCHEMA);
            jdbc.execute("set search_path to " + SCHEMA);
            String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
            Matcher table = Pattern.compile("(?is)create table if not exists ctxa_agent_registration\\s*\\(.*?\\n\\);")
                    .matcher(schema);
            if (!table.find()) {
                throw new IllegalStateException("The schema holds no agent registration table");
            }
            jdbc.execute(table.group().replace(";", ""));
            Matcher indexes = Pattern.compile("(?is)create (?:unique )?index if not exists \\S+\\s+on ctxa_agent_registration[^;]*;")
                    .matcher(schema);
            while (indexes.find()) {
                jdbc.execute(indexes.group().replace(";", ""));
            }
            return new JdbcAgentRegistry(jdbc);
        } catch (SQLException | IOException e) {
            throw new IllegalStateException("The test database could not be opened", e);
        }
    }

    @AfterEach
    void dropSchema() {
        if (jdbc != null) {
            jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        }
        if (dataSource != null) {
            dataSource.destroy();
        }
    }
}
