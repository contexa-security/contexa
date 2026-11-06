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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A database that kept the tracked sessions under their raw identifiers keeps them under their references once Contexa
 * starts: every row is moved, and a session forced out stays forced out, also when a row of its reference was written
 * meanwhile. It runs only against the isolated database named by {@code CONTEXA_TEST_DB_URL}, in a schema of its own
 * that it drops afterwards.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ActiveSessionReferencesTest {

    private static final String SCHEMA = "active_session_reference_test";
    private static final LocalDateTime AT = LocalDateTime.of(2026, 11, 6, 9, 0);

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;

    @BeforeEach
    void setUp() throws Exception {
        Connection connection = DriverManager.getConnection(System.getenv("CONTEXA_TEST_DB_URL"),
                System.getenv("CONTEXA_TEST_DB_USERNAME"), System.getenv("CONTEXA_TEST_DB_PASSWORD"));
        dataSource = new SingleConnectionDataSource(connection, true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        jdbc.execute("create schema " + SCHEMA);
        jdbc.execute("set search_path to " + SCHEMA);
        jdbc.execute(activeSessionsDdl());
    }

    @AfterEach
    void tearDown() {
        if (jdbc != null) {
            jdbc.execute("drop schema if exists " + SCHEMA + " cascade");
        }
        if (dataSource != null) {
            dataSource.destroy();
        }
    }

    @Test
    void theRowsKeptUnderRawIdentifiersAreKeptUnderTheirReferencesAndAForcedOutSessionStaysOut() {
        row("RAW-ACTIVE", "alice", false);
        row("RAW-FORCED-OUT", "bob", true);
        // A node already on references tracked the session again while its raw row was forced out.
        row("RAW-OUT-RETRACKED", "carol", true);
        row(ref("RAW-OUT-RETRACKED"), "carol", false);
        // And the other way round: the reference row was forced out, the raw one was not.
        row("RAW-RETRACKED-OUT", "dave", false);
        row(ref("RAW-RETRACKED-OUT"), "dave", true);
        row(ref("ALREADY-A-REFERENCE"), "erin", false);

        ActiveSessionReferences references = new ActiveSessionReferences(jdbc);

        assertThat(references.referenceStoredSessions()).isEqualTo(4);
        assertThat(jdbc.queryForList("select session_id from ctxa_active_sessions", String.class))
                .containsExactlyInAnyOrder(ref("RAW-ACTIVE"), ref("RAW-FORCED-OUT"), ref("RAW-OUT-RETRACKED"),
                        ref("RAW-RETRACKED-OUT"), ref("ALREADY-A-REFERENCE"))
                .allMatch(id -> id.matches("sid-[0-9a-f]{24}"));
        assertThat(expired(ref("RAW-ACTIVE"))).isFalse();
        assertThat(expired(ref("RAW-FORCED-OUT"))).isTrue();
        assertThat(expired(ref("RAW-OUT-RETRACKED"))).isTrue();
        assertThat(expired(ref("RAW-RETRACKED-OUT"))).isTrue();
        assertThat(expired(ref("ALREADY-A-REFERENCE"))).isFalse();
        Map<String, Object> moved = jdbc.queryForMap("select user_id, username, client_ip, user_agent "
                + "from ctxa_active_sessions where session_id = ?", ref("RAW-ACTIVE"));
        assertThat(moved).containsEntry("user_id", "alice").containsEntry("username", "alice")
                .containsEntry("client_ip", "10.0.0.7").containsEntry("user_agent", "browser");

        // Once moved, a start moves nothing.
        assertThat(references.referenceStoredSessions()).isZero();
    }

    private void row(String sessionId, String user, boolean expired) {
        jdbc.update("insert into ctxa_active_sessions (session_id, client_ip, created_at, expired, last_accessed_at, "
                        + "user_agent, user_id, username) values (?, ?, ?, ?, ?, ?, ?, ?)", sessionId, "10.0.0.7",
                Timestamp.valueOf(AT), expired, Timestamp.valueOf(AT.plusMinutes(5)), "browser", user, user);
    }

    private boolean expired(String sessionId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("select expired from ctxa_active_sessions where session_id = ?",
                Boolean.class, sessionId));
    }

    private static String ref(String sessionId) {
        return RequestFactRedaction.sessionReference(sessionId);
    }

    /** The table exactly as the canonical schema creates it. */
    private static String activeSessionsDdl() throws Exception {
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table ctxa_active_sessions\\s*\\(.*?\\n\\);").matcher(schema);
        assertThat(table.find()).isTrue();
        return table.group().replace(";", "");
    }
}
