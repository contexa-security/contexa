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

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K35 on a real database: the user name of ctxa_one_time_tokens was 50 characters long before the schema made it 100.
 * The start's maintenance widens a shorter column, leaves a longer one as it is and changes nothing the second time.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class SchemaVarcharWideningPostgresTest {

    private static final String SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final String LENGTH = "SELECT character_maximum_length FROM information_schema.columns "
            + "WHERE table_schema = current_schema() AND table_name = 'ctxa_one_time_tokens' AND column_name = 'username'";

    @Test
    void aNewDatabaseHasTheLongUserName() throws Exception {
        try (PostgresTestDatabase database = PostgresTestDatabase.empty()) {
            install(database.dataSource());

            assertThat(database.jdbcTemplate().queryForObject(LENGTH, Integer.class)).isEqualTo(100);
        }
    }

    @Test
    void aDatabaseWithTheShortUserNameIsWidenedOnceAndKeepsItsTokens() throws Exception {
        try (PostgresTestDatabase database = PostgresTestDatabase.empty()) {
            install(database.dataSource());
            JdbcTemplate jdbc = database.jdbcTemplate();
            jdbc.execute("ALTER TABLE ctxa_one_time_tokens ALTER COLUMN username TYPE varchar(50)");
            jdbc.update("INSERT INTO ctxa_one_time_tokens (token_value, username, expires_at) "
                    + "VALUES ('kept-token', 'short-name', now())");

            IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(database.dataSource(), null, false);

            assertThat(jdbc.queryForObject(LENGTH, Integer.class)).isEqualTo(100);
            String longName = "a".repeat(64) + "@example.com";
            jdbc.update("INSERT INTO ctxa_one_time_tokens (token_value, username, expires_at) VALUES ('long-token', ?, now())",
                    longName);
            assertThat(jdbc.queryForObject("SELECT username FROM ctxa_one_time_tokens WHERE token_value = 'kept-token'",
                    String.class)).as("the tokens stay").isEqualTo("short-name");

            // A second start finds the column long enough: the widening is left out of its maintenance.
            assertThat(IamSeedDataAutoConfiguration.withoutNeedlessWidening(database.dataSource(),
                    "alter table ctxa_one_time_tokens alter column username type varchar(100);")).isEmpty();
            IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(database.dataSource(), null, false);
            assertThat(jdbc.queryForObject(LENGTH, Integer.class)).isEqualTo(100);
        }
    }

    @Test
    void aLongerColumnIsNeverShortened() throws Exception {
        try (PostgresTestDatabase database = PostgresTestDatabase.empty()) {
            install(database.dataSource());
            JdbcTemplate jdbc = database.jdbcTemplate();
            jdbc.execute("ALTER TABLE ctxa_one_time_tokens ALTER COLUMN username TYPE varchar(255)");

            IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(database.dataSource(), null, false);

            assertThat(jdbc.queryForObject(LENGTH, Integer.class)).isEqualTo(255);
        }
    }

    @Test
    void aWideningOfAMissingColumnOrAnotherTypeIsLeftOut() throws Exception {
        try (PostgresTestDatabase database = PostgresTestDatabase.empty()) {
            install(database.dataSource());
            DataSource dataSource = database.dataSource();

            assertThat(IamSeedDataAutoConfiguration.withoutNeedlessWidening(dataSource,
                    "alter table ctxa_one_time_tokens alter column no_such_column type varchar(100);")).isEmpty();
            assertThat(IamSeedDataAutoConfiguration.withoutNeedlessWidening(dataSource,
                    "alter table ctxa_one_time_tokens alter column expires_at type varchar(100);")).isEmpty();
            assertThat(IamSeedDataAutoConfiguration.withoutNeedlessWidening(dataSource,
                    "create index if not exists kept_index on ctxa_one_time_tokens (username);"))
                    .as("other statements stay").contains("kept_index");
        }
    }

    private static void install(DataSource dataSource) throws Exception {
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, SCHEMA,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource(SCHEMA).getContentAsString(StandardCharsets.UTF_8)));
    }
}
