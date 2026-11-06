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

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationProvider;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.token.service.AccountTokenGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * RC PR-44 on the database customers run. Spring's authorization service looks its columns up under the standard table
 * name; under the {@code ctxa_} name it found none and took every column for a BLOB. H2 reads the bytes of such a value
 * back as the text they encode, PostgreSQL stores them in a text column in its hex form ({@code \x7b22...}), so only this
 * database shows what a customer gets. The sign-ins go through Contexa's real grant provider, with its transaction.
 */
class OAuth2AuthorizationStoragePostgresTest {

    private static final String SCHEMA_SCRIPT = "contexa-oauth2-authorization-schema.sql";
    private static final String CANONICAL_SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final String TABLE = "ctxa_oauth2_authorization";
    private static final List<String> VALUE_COLUMNS = List.of("authorization_code_value", "access_token_value",
            "oidc_id_token_value", "refresh_token_value", "user_code_value", "device_code_value");
    /** The columns written from a text or a map, without the ones of the grants a sign-in does not use. */
    private static final List<String> STORED_COLUMNS = List.of("attributes", "access_token_value", "access_token_metadata",
            "refresh_token_value", "refresh_token_metadata");

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private TransactionTemplate transactions;
    private AuthContextProperties properties;
    private DeviceAwareOAuth2AuthorizationService service;
    private AuthenticatedUserGrantAuthenticationProvider provider;
    private RegisteredClient client;

    @BeforeEach
    void openDatabase() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        transactions = new TransactionTemplate(new DataSourceTransactionManager(database.dataSource()));
        properties = new AuthContextProperties();
        properties.getOauth2().setIssuerUri("https://issuer.example.test");
        properties.getOauth2().setClientSecret("postgres-test-unique-client-secret");
    }

    @AfterEach
    void closeDatabase() {
        AuthorizationServerContextHolder.resetContext();
        if (database != null) {
            database.close();
        }
    }

    // PG-01: the measurement, 200 then 500 then 500
    @Test
    void aUserSignsInAgainAndAgainOnTheTablesOfTheInstalledSchema() throws IOException {
        installCanonicalTables();
        start();

        OAuth2AccessTokenAuthenticationToken first = signIn("alice");
        OAuth2AccessTokenAuthenticationToken second = signIn("alice");
        OAuth2AccessTokenAuthenticationToken third = signIn("alice");

        assertThat(List.of(first, second, third)).hasSize(3);
        assertStoredAsWritten(third);
        OAuth2Authorization latest = service.findByToken(third.getRefreshToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
        assertThat(latest).isNotNull();
        assertThat(latest.getPrincipalName()).isEqualTo("alice");
        assertThat(latest.getRefreshToken().isActive()).isTrue();
        assertThat(latest.<String>getAttribute("device_id")).isEqualTo("device-1");
    }

    // PG-02: what the script a start runs creates is what the canonical schema creates
    @Test
    void aNewDatabaseGetsTextColumnsWhicheverScriptCreatesTheTable() {
        start();

        assertThat(columnTypes()).as("the columns of the tokens").containsOnly("text");
        signIn("alice");
        assertStoredAsWritten(signIn("alice"));
    }

    // PG-03: a database whose table the script created while it still said BYTEA
    @Test
    void aTableWithBinaryTokenColumnsKeepsWorking() {
        new ResourceDatabasePopulator(new ClassPathResource(SCHEMA_SCRIPT)).execute(database.dataSource());
        for (String column : VALUE_COLUMNS) {
            if ("text".equals(typeOf(column))) {
                jdbc.execute("alter table " + TABLE + " alter column " + column + " type bytea using convert_to(" + column + ", 'UTF8')");
            }
        }
        start();

        OAuth2AccessTokenAuthenticationToken first = signIn("alice");
        OAuth2AccessTokenAuthenticationToken second = signIn("alice");

        assertThat(columnTypes()).containsOnly("bytea");
        assertThat(service.findByToken(first.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN)).isNotNull();
        OAuth2Authorization latest = service.findByToken(second.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertThat(latest.getAccessToken().getToken().getTokenValue()).isEqualTo(second.getAccessToken().getTokenValue());
        assertThat(latest.getRefreshToken().getToken().getTokenValue()).isEqualTo(second.getRefreshToken().getTokenValue());
    }

    // PG-04: rows the earlier build wrote stop neither the user nor anybody else
    @Test
    void aRowStoredInHexFormNeitherStopsTheNextSignInNorSurvivesIt() throws IOException {
        installCanonicalTables();
        start();
        signIn("alice");
        OAuth2AccessTokenAuthenticationToken other = signIn("bob");
        breakStoredRowsOf("alice");
        assertThat(jdbc.queryForObject("select attributes from " + TABLE + " where principal_name = 'alice'", String.class))
                .startsWith("\\x7b22");

        OAuth2AccessTokenAuthenticationToken next = signIn("alice");
        OAuth2AccessTokenAuthenticationToken afterThat = signIn("alice");

        assertThat(rowsOf("alice")).as("the unreadable row is gone, the two new ones stay").isEqualTo(2);
        assertStoredAsWritten(next);
        assertStoredAsWritten(afterThat);
        assertThat(service.findByToken(other.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN))
                .as("another user's login").isNotNull();
    }

    // PG-05: outside a transaction the read ends read-only, and the removal needs one of its own
    @Test
    void anUnreadableRowFoundOutsideATransactionIsRemovedAsWell() throws IOException {
        installCanonicalTables();
        start();
        signIn("alice");
        breakStoredRowsOf("alice");

        assertThat(service.findActiveByPrincipalName("alice")).isEmpty();

        assertThat(rowsOf("alice")).isZero();
    }

    // PG-06: a table of the application under the standard name is neither read nor asked about
    @Test
    void theApplicationsOwnTableOfTheStandardNameDecidesNothing() throws IOException {
        installCanonicalTables();
        jdbc.execute("create table oauth2_authorization (id varchar(100) primary key, attributes bytea, access_token_value bytea, "
                + "access_token_metadata bytea, refresh_token_value bytea, refresh_token_metadata bytea)");
        jdbc.update("insert into oauth2_authorization (id, attributes) values ('host-row', ?)", (Object) new byte[]{1, 2, 3});
        start();

        signIn("alice");
        assertStoredAsWritten(signIn("alice"));

        assertThat(jdbc.queryForObject("select count(*) from oauth2_authorization", Integer.class)).isEqualTo(1);
    }

    // PG-07: the limit on logins reads the earlier login and writes it back
    @Test
    void theEarlierLoginEndsWhenOneLoginIsAllowed() throws IOException {
        installCanonicalTables();
        properties.setAllowMultipleLogins(false);
        start();

        OAuth2AccessTokenAuthenticationToken first = signIn("alice");
        OAuth2AccessTokenAuthenticationToken second = signIn("alice");

        OAuth2Authorization earlier = service.findByToken(first.getRefreshToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
        assertThat(earlier.getRefreshToken().isInvalidated()).isTrue();
        assertThat(earlier.getAccessToken().isInvalidated()).isTrue();
        OAuth2Authorization current = service.findByToken(second.getRefreshToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
        assertThat(current.getRefreshToken().isActive()).isTrue();
    }

    // PG-08: what a start stored the next start reads
    @Test
    void aNewStartReadsWhatTheEarlierOneStored() throws IOException {
        installCanonicalTables();
        start();
        OAuth2AccessTokenAuthenticationToken before = signIn("alice");

        start();

        assertThat(service.findByToken(before.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN)).isNotNull();
        assertStoredAsWritten(signIn("alice"));
    }

    // PG-09: a refresh compares what the stored token names with the account, so the claim reads back as it was written
    @Test
    void theRolesAStoredTokenNamesReadBackForARefreshToCompare() throws IOException {
        installCanonicalTables();
        start();
        OAuth2AccessTokenAuthenticationToken signedIn = signIn("alice");

        OAuth2Authorization stored = service.findByToken(signedIn.getRefreshToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);

        Object named = stored.getAccessToken().getClaims().get(AccountTokenGuard.ROLES_CLAIM);
        assertThat(AccountTokenGuard.namesRightsBeyond(named,
                User.withUsername("alice").password("{noop}x").roles("USER").build())).isFalse();
        assertThat(AccountTokenGuard.namesRightsBeyond(named,
                User.withUsername("alice").password("{noop}x").authorities(List.of()).build())).isTrue();
    }

    private void start() {
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(transactions, properties);
        RegisteredClientRepository clients = configuration.registeredClientRepository(jdbc);
        client = clients.findByClientId(properties.getOauth2().getClientId());
        service = (DeviceAwareOAuth2AuthorizationService) configuration.authorizationService(jdbc, clients);

        AuthorizationServerContext serverContext = mock(AuthorizationServerContext.class);
        when(serverContext.getIssuer()).thenReturn(properties.getOauth2().getIssuerUri());
        when(serverContext.getAuthorizationServerSettings()).thenReturn(configuration.authorizationServerSettings());
        AuthorizationServerContextHolder.setContext(serverContext);

        JWKSource<SecurityContext> keys = configuration.jwkSource();
        JwtGenerator jwtGenerator = new JwtGenerator(configuration.jwtEncoder(keys));
        jwtGenerator.setJwtCustomizer(configuration.tokenCustomizer(none(), none(), none()));
        provider = new AuthenticatedUserGrantAuthenticationProvider(service,
                new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2RefreshTokenGenerator()), users(), transactions);
    }

    private OAuth2AccessTokenAuthenticationToken signIn(String username) {
        OAuth2ClientAuthenticationToken caller = new OAuth2ClientAuthenticationToken(
                client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
        return (OAuth2AccessTokenAuthenticationToken) provider.authenticate(
                new AuthenticatedUserGrantAuthenticationToken(caller, username, "device-1", Map.of()));
    }

    private static UserRepository users() {
        UserRepository users = mock(UserRepository.class);
        for (String name : List.of("alice", "bob")) {
            Users user = mock(Users.class);
            when(user.getUsername()).thenReturn(name);
            when(user.getRoleNames()).thenReturn(List.of("ROLE_USER"));
            when(users.findByUsernameWithGroupsRolesAndPermissions(name)).thenReturn(Optional.of(user));
        }
        return users;
    }

    /** The statements of the schema a Contexa installation runs that create the authorization server's tables. */
    private void installCanonicalTables() throws IOException {
        String schema = new ClassPathResource(CANONICAL_SCHEMA).getContentAsString(StandardCharsets.UTF_8);
        for (String statement : IamSeedDataAutoConfiguration.splitSqlStatements(schema)) {
            if (statement.toLowerCase(Locale.ROOT).contains("create table ctxa_oauth2_")) {
                jdbc.execute(statement);
            }
        }
        assertThat(columnTypes()).as("the installed columns of the tokens").containsOnly("text");
    }

    /** As the earlier build wrote them: the bytes of the value into the text column, which PostgreSQL keeps in hex form. */
    private void breakStoredRowsOf(String principal) {
        for (String column : STORED_COLUMNS) {
            jdbc.queryForList("select id, " + column + " as stored from " + TABLE + " where principal_name = ? and " + column
                    + " is not null", principal).forEach(row -> jdbc.update("update " + TABLE + " set " + column + " = ? where id = ?",
                    row.get("stored").toString().getBytes(StandardCharsets.UTF_8), row.get("id")));
        }
    }

    private void assertStoredAsWritten(OAuth2AccessTokenAuthenticationToken signIn) {
        Map<String, Object> row = jdbc.queryForMap("select attributes, access_token_value, access_token_metadata, refresh_token_value "
                + "from " + TABLE + " where access_token_value = ?", signIn.getAccessToken().getTokenValue());
        assertThat(row.get("attributes").toString()).startsWith("{");
        assertThat(row.get("access_token_metadata").toString()).startsWith("{");
        assertThat(row.get("refresh_token_value")).isEqualTo(signIn.getRefreshToken().getTokenValue());
        assertThat(service.findByToken(signIn.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN)).isNotNull();
    }

    private int rowsOf(String principal) {
        return jdbc.queryForObject("select count(*) from " + TABLE + " where principal_name = ?", Integer.class, principal);
    }

    private List<String> columnTypes() {
        return VALUE_COLUMNS.stream().map(this::typeOf).toList();
    }

    private String typeOf(String column) {
        return jdbc.queryForObject("select data_type from information_schema.columns where table_name = ? and column_name = ?",
                String.class, TABLE, column);
    }

    /** docs/agent OC-1: no delegation registry and no agent directory, so no delegation claim. */
    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> none() {
        return mock(ObjectProvider.class);
    }
}
