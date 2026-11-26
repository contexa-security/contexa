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

import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Bridge v2 B5-1 (DB-1, DB-8, decision 5) on the database customers run: a database of an older version moves to the
 * address rule (unique among Contexa's own accounts only, whatever its case; copies may share one or have none), a
 * database whose accounts already share an address apart from its case is left as it is, and the console counts the
 * users no code can reach.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@DisplayName("사용자 메일 규칙의 기존 DB 이전과 콘솔 집계(실제 PostgreSQL)")
class ContexaUserEmailScopePostgresTest {

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;

    @BeforeEach
    void install() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        IamSeedDataAutoConfiguration.executeSchemaSql(database.dataSource(), "META-INF/contexa/db/schema.sql",
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8)));
    }

    @AfterEach
    void close() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    @DisplayName("옛 판의 메일 고유 제약과 NOT NULL을 옮기고 부분 고유 색인을 만든다")
    void anOlderDatabaseMovesToTheRule() {
        olderAddressRule();

        ContexaUserEmailScope.Outcome outcome = ContexaUserEmailScope.apply(database.dataSource());

        assertThat(outcome).isEqualTo(ContexaUserEmailScope.Outcome.APPLIED);
        assertThat(addressOnlyUniqueConstraints()).isZero();
        assertThat(jdbc.queryForObject("select is_nullable from information_schema.columns where table_schema = "
                + "current_schema() and table_name = 'ctxa_users' and column_name = 'email'", String.class)).isEqualTo("YES");
        assertThat(indexExists()).isTrue();
    }

    @Test
    @DisplayName("옮긴 뒤 사본끼리는 같은 메일과 빈 메일을 저장할 수 있고, Contexa 계정끼리는 대소문자만 달라도 거부된다")
    void copiesMayShareAnAddressAccountsMayNot() {
        olderAddressRule();
        ContexaUserEmailScope.apply(database.dataSource());

        user("brg_a", "team@corp.example", true);
        user("brg_b", "team@corp.example", true);
        user("brg_c", null, true);
        user("admin", "Admin@corp.example", false);

        assertThat(jdbc.queryForObject("select count(*) from ctxa_users where lower(email) = 'team@corp.example'",
                Integer.class)).isEqualTo(2);
        assertThatThrownBy(() -> user("other-admin", "admin@CORP.example", false))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("Contexa 계정끼리 대소문자만 다른 메일이 이미 있으면 아무것도 바꾸지 않는다")
    void accountsThatShareAnAddressLeaveTheDatabaseAsItIs() {
        olderAddressRule();
        user("ann", "Ann@corp.example", false);
        user("ann2", "ann@corp.example", false);

        ContexaUserEmailScope.Outcome outcome = ContexaUserEmailScope.apply(database.dataSource());

        assertThat(outcome).isEqualTo(ContexaUserEmailScope.Outcome.SHARED_ACCOUNT_ADDRESSES);
        assertThat(addressOnlyUniqueConstraints()).isEqualTo(1);
        assertThat(indexExists()).isFalse();
        assertThat(jdbc.queryForObject("select is_nullable from information_schema.columns where table_schema = "
                + "current_schema() and table_name = 'ctxa_users' and column_name = 'email'", String.class)).isEqualTo("NO");
    }

    @Test
    @DisplayName("새로 설치한 DB에는 색인만 만들고, 다시 돌리면 바꿀 것이 없다")
    void aDatabaseUnderTheRuleIsLeftAsItIs() {
        assertThat(ContexaUserEmailScope.apply(database.dataSource())).isEqualTo(ContexaUserEmailScope.Outcome.APPLIED);

        assertThat(ContexaUserEmailScope.apply(database.dataSource())).isEqualTo(ContexaUserEmailScope.Outcome.NOT_NEEDED);
    }

    @Test
    @DisplayName("콘솔 집계는 메일 없는 사용자, 예전 가짜 메일 사용자, 같은 메일 사용자를 추가 인증에 답할 수 없는 사용자로 센다")
    void theConsoleCountsTheUsersNoCodeCanReach() {
        ContexaUserEmailScope.apply(database.dataSource());
        user("brg_none", null, true);
        user("brg_made", "brg_made@shadow.contexa.local", true);
        user("brg_team1", "team@corp.example", true);
        user("brg_team2", "TEAM@corp.example", true);
        user("brg_solo", "solo@corp.example", true);

        Long count = new NamedParameterJdbcTemplate(jdbc).queryForObject(
                "select count(*) " + UserRepository.WITHOUT_VERIFICATION_FACTOR,
                new MapSqlParameterSource()
                        .addValue("mailDelivers", true)
                        .addValue("passkeysWork", false)
                        .addValue("syntheticMail", "%@shadow.contexa.local")
                        .addValue("agentMail", "%@agents.contexa.local"),
                Long.class);

        assertThat(count).isEqualTo(4L);
    }

    /** The address rule of an older version: NOT NULL and unique among every user, case and all. */
    private void olderAddressRule() {
        jdbc.execute("alter table ctxa_users alter column email set not null");
        jdbc.execute("alter table ctxa_users add constraint ctxa_users_email_key unique (email)");
    }

    private void user(String username, String email, boolean copy) {
        jdbc.update("insert into ctxa_users (username, email, password, name, bridge_managed, external_auth_only) "
                + "values (?, ?, 'x', ?, ?, ?)", username, email, username, copy, copy);
    }

    private int addressOnlyUniqueConstraints() {
        return jdbc.queryForObject("""
                select count(*) from pg_constraint c join pg_class t on t.oid = c.conrelid
                  join pg_attribute a on a.attrelid = t.oid and a.attnum = c.conkey[1]
                 where t.relname = 'ctxa_users' and c.contype = 'u' and array_length(c.conkey, 1) = 1
                   and a.attname = 'email'""", Integer.class);
    }

    private boolean indexExists() {
        return Boolean.TRUE.equals(jdbc.queryForObject("select exists (select 1 from pg_indexes where indexname = ?)",
                Boolean.class, ContexaUserEmailScope.INDEX));
    }
}
