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
package io.contexa.autoconfigure.jdbc;

import io.contexa.contexacommon.jdbc.LibraryTableNames;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.JdbcOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.sql.ResultSet;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class LibraryTableNamesTest {

    private static final Pattern TABLE_IN_SQL = Pattern.compile("(?i)\\b(?:from|into|update|join|table)\\s+([a-z0-9_]+)");

    private static final List<Class<?>> LIBRARY_CLASSES = List.of(
            JdbcOneTimeTokenService.class,
            JdbcUserCredentialRepository.class,
            JdbcPublicKeyCredentialUserEntityRepository.class,
            JdbcOAuth2AuthorizationService.class,
            JdbcOAuth2AuthorizationConsentService.class,
            JdbcRegisteredClientRepository.class);

    /** Every SQL text the libraries keep in a constant: a library that changes its tables fails this test, not production. */
    private static List<String> librarySql() throws IllegalAccessException {
        List<String> sql = new ArrayList<>();
        for (Class<?> type : LIBRARY_CLASSES) {
            for (Field field : type.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                    field.setAccessible(true);
                    String value = (String) field.get(null);
                    if (value != null && TABLE_IN_SQL.matcher(value).find()) {
                        sql.add(value);
                    }
                }
            }
        }
        return sql;
    }

    @Test
    void theTableMapNamesEveryTableTheLibrariesWriteTo() throws Exception {
        Set<String> found = new TreeSet<>();
        for (String sql : librarySql()) {
            Matcher matcher = TABLE_IN_SQL.matcher(sql);
            while (matcher.find()) {
                found.add(matcher.group(1).toLowerCase());
            }
        }

        assertThat(found).as("the tables named in the libraries' SQL").isEqualTo(new TreeSet<>(LibraryTableNames.TABLES.keySet()));
    }

    @Test
    void everyLibrarySqlTextComesOutWithOnlyPrefixedTables() throws Exception {
        List<String> sql = librarySql();
        assertThat(sql).isNotEmpty();
        for (String statement : sql) {
            String renamed = LibraryTableNames.rewrite(statement);
            Matcher matcher = TABLE_IN_SQL.matcher(renamed);
            while (matcher.find()) {
                assertThat(matcher.group(1)).as(renamed).startsWith("ctxa_");
            }
            assertThat(LibraryTableNames.rewrite(renamed)).as("a second pass changes nothing").isEqualTo(renamed);
        }
    }

    @Test
    void aNameThatOnlyContainsALibraryTableIsLeftAlone() {
        String sql = "select * from my_user_entities x join user_entities_archive y on 1 = 1 where one_time_tokens_count > 0";

        assertThat(LibraryTableNames.rewrite(sql)).isEqualTo(sql);
        assertThat(LibraryTableNames.rewrite("SELECT * FROM ONE_TIME_TOKENS")).isEqualTo("SELECT * FROM CTXA_ONE_TIME_TOKENS");
        assertThat(LibraryTableNames.rewrite(null)).isNull();
    }

    @Test
    void theOneTimeTokenServiceUsesContexasTableAndLeavesTheApplicationsOwn() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource("jdbc:h2:mem:library-names;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        String ddl = " (token_value varchar(36) primary key, username varchar(50) not null, expires_at timestamp not null)";
        jdbc.execute("create table ctxa_one_time_tokens" + ddl);
        jdbc.execute("create table one_time_tokens" + ddl);
        jdbc.update("insert into one_time_tokens (token_value, username, expires_at) values ('host-token', 'host', "
                + "timestampadd(hour, 1, current_timestamp))");

        JdbcOperations wrapped = LibraryTableNames.wrap(jdbc);
        assertThat(LibraryTableNames.wrap(wrapped)).as("wrapping twice is the same wrapper").isSameAs(wrapped);
        JdbcOneTimeTokenService service = new JdbcOneTimeTokenService(wrapped);

        OneTimeToken token = service.generate(new GenerateOneTimeTokenRequest("alice"));

        assertThat(jdbc.queryForObject("select count(*) from ctxa_one_time_tokens", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from one_time_tokens", Integer.class))
                .as("the application's own table is not written").isEqualTo(1);
        assertThat(service.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue()))).isNotNull();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_one_time_tokens", Integer.class)).isZero();
        assertThat(service.consume(new OneTimeTokenAuthenticationToken("host-token")))
                .as("a token of the application's table is not Contexa's to consume").isNull();
        assertThat(jdbc.queryForObject("select count(*) from one_time_tokens", Integer.class)).isEqualTo(1);
    }

    // PR-44: Spring's authorization service asks the database about its columns under the standard table name
    @Test
    void aLibraryThatAsksAboutItsTableIsAnsweredForContexasTableInEitherCase() {
        JdbcTemplate jdbc = database("library-columns");
        jdbc.execute("create table ctxa_oauth2_authorization (id varchar(100) primary key, attributes varchar(4000))");
        jdbc.execute("create table oauth2_authorization (id varchar(100) primary key, attributes blob)");

        JdbcOperations wrapped = LibraryTableNames.wrap(jdbc);

        assertThat(columnType(wrapped, "OAUTH2_AUTHORIZATION", "ATTRIBUTES")).as("the application's table is not the one asked about")
                .isEqualTo(Types.VARCHAR);
        assertThat(columnType(wrapped, "oauth2_authorization", "attributes")).as("a database that keeps the name in lower case")
                .isNull();
        assertThat(columnType(jdbc, "OAUTH2_AUTHORIZATION", "ATTRIBUTES")).as("without the wrapper nothing changes").isEqualTo(Types.BLOB);
    }

    // PR-44: Spring reads a binary column as bytes only when it is told BLOB; a driver says BINARY for PostgreSQL's bytea
    @Test
    void aColumnKeptAsBytesIsReportedAsTheBlobTheLibraryReadsAsBytes() {
        JdbcTemplate jdbc = database("library-binary-columns");
        jdbc.execute("create table ctxa_oauth2_authorization (id varchar(100) primary key, access_token_value varbinary(4000))");

        assertThat(columnType(jdbc, "CTXA_OAUTH2_AUTHORIZATION", "ACCESS_TOKEN_VALUE")).isEqualTo(Types.VARBINARY);
        assertThat(columnType(LibraryTableNames.wrap(jdbc), "OAUTH2_AUTHORIZATION", "ACCESS_TOKEN_VALUE")).isEqualTo(Types.BLOB);
    }

    private static JdbcTemplate database(String name) {
        return new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:" + name + ";DB_CLOSE_DELAY=-1", "sa", ""));
    }

    /** What Spring's authorization service does when it is built. */
    private static Integer columnType(JdbcOperations jdbc, String table, String column) {
        return jdbc.execute((ConnectionCallback<Integer>) connection -> {
            ResultSet columns = connection.getMetaData().getColumns(null, null, table, column);
            return columns.next() ? columns.getInt("DATA_TYPE") : null;
        });
    }
}
