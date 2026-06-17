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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailOneTimeTokenServiceTest {

    private EmbeddedDatabase db;
    private JdbcTemplate jdbcTemplate;
    private TransactionTemplate transactionTemplate;

    @Mock
    private EmailService emailService;

    @Mock
    private AuthContextProperties authContextProperties;

    @Mock
    private MfaSettings mfaSettings;

    @BeforeEach
    void setUp() {
        db = new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .setName("ott_test_db_" + System.currentTimeMillis())
                .build();
        jdbcTemplate = new JdbcTemplate(db);
        PlatformTransactionManager txManager = new JdbcTransactionManager(db);
        transactionTemplate = new TransactionTemplate(txManager);

        jdbcTemplate.execute("CREATE TABLE one_time_tokens (" +
                "token_value VARCHAR(256) NOT NULL, " +
                "username VARCHAR(256) NOT NULL, " +
                "expires_at TIMESTAMP NOT NULL, " +
                "PRIMARY KEY (token_value))");

        jdbcTemplate.execute("CREATE TABLE users (" +
                "username VARCHAR(256) NOT NULL, " +
                "email VARCHAR(256) NOT NULL, " +
                "PRIMARY KEY (username))");

        when(authContextProperties.getMfa()).thenReturn(mfaSettings);
        when(mfaSettings.getOtpTokenValiditySeconds()).thenReturn(300); // 5 minutes
    }

    @AfterEach
    void tearDown() {
        if (db != null) {
            db.shutdown();
        }
    }

    @Test
    @DisplayName("generate should create a token, store it in H2, and send HTML email successfully")
    void generateTokenSuccess() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        jdbcTemplate.update("INSERT INTO users(username, email) VALUES(?, ?)", "testuser", "user@contexa.io");

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("testuser");
        OneTimeToken token = service.generate(request);

        assertThat(token).isNotNull();
        assertThat(token.getUsername()).isEqualTo("testuser");
        assertThat(token.getTokenValue()).isNotEmpty();

        // Verify it exists in H2 database
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM one_time_tokens WHERE token_value = ?", Integer.class, token.getTokenValue()
        );
        assertThat(count).isEqualTo(1);

        // Verify email sent with token
        verify(emailService).sendHtmlMessage(
                eq("user@contexa.io"),
                contains("Authentication Code"),
                contains(token.getTokenValue())
        );
    }

    @Test
    @DisplayName("generate should use username as recipient email if not found in users table")
    void generateTokenUsesUsernameAsFallbackEmail() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("fallback@contexa.io");
        OneTimeToken token = service.generate(request);

        verify(emailService).sendHtmlMessage(
                eq("fallback@contexa.io"),
                anyString(),
                contains(token.getTokenValue())
        );
    }

    @Test
    @DisplayName("generate should allow requested email only when it matches the registered user email")
    void generateTokenAllowsMatchingRequestedEmail() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        jdbcTemplate.update("INSERT INTO users(username, email) VALUES(?, ?)", "testuser", "user@contexa.io");

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        OneTimeToken token = service.generate(new EmailGenerateOneTimeTokenRequest("testuser", "USER@CONTEXA.IO"));

        assertThat(token).isNotNull();
        verify(emailService).sendHtmlMessage(
                eq("user@contexa.io"),
                anyString(),
                contains(token.getTokenValue())
        );
    }

    @Test
    @DisplayName("generate should reject requested email that differs from the registered user email")
    void generateTokenRejectsMismatchedRequestedEmail() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        jdbcTemplate.update("INSERT INTO users(username, email) VALUES(?, ?)", "testuser", "user@contexa.io");

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        assertThatThrownBy(() -> service.generate(new EmailGenerateOneTimeTokenRequest("testuser", "attacker@example.com")))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("Invalid one-time token delivery request");

        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM one_time_tokens", Integer.class);
        assertThat(count).isZero();
        verify(emailService, never()).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("generate should throw IllegalStateException when mail sender not configured and failOnEmailError is true")
    void generateThrowsExceptionWhenMailSenderNotConfigured() {
        when(emailService.isMailSenderConfigured()).thenReturn(false);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("testuser");

        assertThatThrownBy(() -> service.generate(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Email sender is not configured");

        verify(emailService, never()).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("generate should NOT throw exception when mail sender not configured but failOnEmailError is false")
    void generateDoesNotThrowExceptionWhenMailSenderNotConfigured() {
        when(emailService.isMailSenderConfigured()).thenReturn(false);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, false
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("testuser");
        OneTimeToken token = service.generate(request);

        assertThat(token).isNotNull();
        // Should still be stored in H2 database
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM one_time_tokens WHERE token_value = ?", Integer.class, token.getTokenValue()
        );
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("generate should propagate RuntimeException when email delivery fails and failOnEmailError is true")
    void generatePropagatesEmailException() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        doThrow(new RuntimeException("Mail server down"))
                .when(emailService).sendHtmlMessage(anyString(), anyString(), anyString());

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("testuser");

        assertThatThrownBy(() -> service.generate(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Mail server down");
    }

    @Test
    @DisplayName("generate should swallow exception when email delivery fails but failOnEmailError is false")
    void generateSwallowsEmailException() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        doThrow(new RuntimeException("Mail server down"))
                .when(emailService).sendHtmlMessage(anyString(), anyString(), anyString());

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, false
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("testuser");
        OneTimeToken token = service.generate(request);

        assertThat(token).isNotNull();
    }

    @Test
    @DisplayName("consume should return token and delete it from H2 database (one-time usage constraint)")
    void consumeTokenDeletesFromStore() {
        // Insert a token manually
        jdbcTemplate.update(
                "INSERT INTO one_time_tokens(token_value, username, expires_at) VALUES(?, ?, ?)",
                "token-123", "testuser", Timestamp.from(Instant.now().plusSeconds(300))
        );

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        OneTimeTokenAuthenticationToken authToken = new OneTimeTokenAuthenticationToken("testuser", "token-123");
        OneTimeToken consumed = service.consume(authToken);

        assertThat(consumed).isNotNull();
        assertThat(consumed.getTokenValue()).isEqualTo("token-123");
        assertThat(consumed.getUsername()).isEqualTo("testuser");

        // Verify it was deleted from H2 database (one-time usage check)
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM one_time_tokens WHERE token_value = ?", Integer.class, "token-123"
        );
        assertThat(count).isZero();
    }

    @Test
    @DisplayName("consume should throw InvalidOneTimeTokenException when token is not found")
    void consumeThrowsExceptionWhenNotFound() {
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        OneTimeTokenAuthenticationToken authToken = new OneTimeTokenAuthenticationToken("testuser", "non-existent-token");

        assertThatThrownBy(() -> service.consume(authToken))
                .isInstanceOf(InvalidOneTimeTokenException.class)
                .hasMessageContaining("Invalid or expired code");
    }
}
