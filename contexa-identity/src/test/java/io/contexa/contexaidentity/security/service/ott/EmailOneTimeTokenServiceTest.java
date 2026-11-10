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
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailOneTimeTokenServiceTest {

    private PostgresTestDatabase database;
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
        database = PostgresTestDatabase.empty();
        jdbcTemplate = database.jdbcTemplate();
        PlatformTransactionManager txManager = new JdbcTransactionManager(database.dataSource());
        transactionTemplate = new TransactionTemplate(txManager);

        jdbcTemplate.execute("CREATE TABLE ctxa_one_time_tokens (" +
                "token_value VARCHAR(256) NOT NULL, " +
                "username VARCHAR(256) NOT NULL, " +
                "expires_at TIMESTAMP NOT NULL, " +
                "PRIMARY KEY (token_value))");

        jdbcTemplate.execute("CREATE TABLE ctxa_users (" +
                "username VARCHAR(256) NOT NULL, " +
                "email VARCHAR(256) NOT NULL, " +
                "PRIMARY KEY (username))");
        jdbcTemplate.update("INSERT INTO ctxa_users(username, email) VALUES(?, ?)", "testuser", "user@contexa.io");

        when(authContextProperties.getMfa()).thenReturn(mfaSettings);
        when(mfaSettings.getOtpTokenValiditySeconds()).thenReturn(300); // 5 minutes
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    @DisplayName("generate should create a token, store it in PostgreSQL, and send HTML email successfully")
    void generateTokenSuccess() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("testuser");
        OneTimeToken token = service.generate(request);

        assertThat(token).isNotNull();
        assertThat(token.getUsername()).isEqualTo("testuser");
        assertThat(token.getTokenValue()).isNotEmpty();

        // Verify it exists in PostgreSQL database
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM ctxa_one_time_tokens WHERE token_value = ?", Integer.class, token.getTokenValue()
        );
        assertThat(count).isEqualTo(1);

        // Verify email sent with token
        verify(emailService).sendHtmlMessage(
                eq("user@contexa.io"),
                contains("Authentication Code"),
                contains(token.getTokenValue())
        );
    }

    /** Anyone may ask in any name: a name with no row is no event of the log, or asking would fill it. */
    @Test
    @DisplayName("a name with no account leaves nothing in the log")
    void aNameWithNoAccountLeavesNothingInTheLog() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        Logger logger = (Logger) LoggerFactory.getLogger(EmailOneTimeTokenService.class);
        ListAppender<ILoggingEvent> events = new ListAppender<>();
        events.start();
        logger.addAppender(events);
        try {
            service.generate(new GenerateOneTimeTokenRequest("nobody@contexa.io"));
        } finally {
            logger.detachAppender(events);
        }

        assertThat(events.list).noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.WARN));
        verify(emailService, never()).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    /** A store that does not answer is an event: only the name with no row is quiet. */
    @Test
    @DisplayName("a lookup that fails is still reported")
    void aLookupThatFailsIsReported() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        jdbcTemplate.execute("DROP TABLE ctxa_users");
        Logger logger = (Logger) LoggerFactory.getLogger(EmailOneTimeTokenService.class);
        ListAppender<ILoggingEvent> events = new ListAppender<>();
        events.start();
        logger.addAppender(events);
        try {
            service.generate(new GenerateOneTimeTokenRequest("nobody@contexa.io"));
        } finally {
            logger.detachAppender(events);
        }

        assertThat(events.list).anyMatch(event -> event.getLevel() == Level.WARN);
    }

    /** A name is what its owner typed at sign-up, and the mail is read as HTML in the owner's mailbox. */
    @Test
    @DisplayName("a name reaches the mail as text, never as markup")
    void aNameReachesTheMailAsText() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        String name = "<a href=\"https://evil.example\">verify</a>";
        jdbcTemplate.update("INSERT INTO ctxa_users(username, email) VALUES(?, ?)", name, "marked@contexa.io");
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        service.generate(new GenerateOneTimeTokenRequest(name));

        verify(emailService).sendHtmlMessage(eq("marked@contexa.io"), anyString(),
                argThat(body -> !body.contains("<a href") && body.contains("&lt;a href")));
    }

    /** The application's own users are in no table of Contexa's, and an application may sign in with an address. */
    @Test
    @DisplayName("generate should use username as recipient email for an account of the store the sign-in reads")
    void generateTokenUsesUsernameAsFallbackEmail() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        service.setUserStore(() -> new InMemoryUserDetailsManager(
                User.withUsername("fallback@contexa.io").password("{noop}x").build()));

        GenerateOneTimeTokenRequest request = new GenerateOneTimeTokenRequest("fallback@contexa.io");
        OneTimeToken token = service.generate(request);

        verify(emailService).sendHtmlMessage(
                eq("fallback@contexa.io"),
                anyString(),
                contains(token.getTokenValue())
        );
    }

    @Test
    @DisplayName("generate should mail nothing and make no code for a name of no account")
    void generateMailsNothingToANameOfNoAccount() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        service.setUserStore(() -> new InMemoryUserDetailsManager(
                User.withUsername("fallback@contexa.io").password("{noop}x").build()));

        OneTimeToken token = service.generate(new GenerateOneTimeTokenRequest("victim@example.test"));

        assertThat(token.getUsername()).isEqualTo("victim@example.test");
        assertThat(token.getTokenValue()).isEmpty();
        verify(emailService, never()).sendHtmlMessage(anyString(), anyString(), anyString());
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM ctxa_one_time_tokens", Integer.class)).isZero();
    }

    /**
     * A code signs in to no account that is locked or disabled, so none is made or mailed for one; the answer is the one a
     * name of no account gets, which tells nothing of the account's state.
     */
    @Test
    @DisplayName("generate should mail nothing to a locked or disabled account, of Contexa's table or of the store, and answer all the same")
    void generateMailsNothingToALockedOrDisabledAccount() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);
        jdbcTemplate.update("INSERT INTO ctxa_users(username, email) VALUES(?, ?)", "disabled-user", "disabled@contexa.io");

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        service.setUserStore(() -> new InMemoryUserDetailsManager(
                User.withUsername("testuser").password("{noop}x").accountLocked(true).build(),
                User.withUsername("disabled-user").password("{noop}x").disabled(true).build(),
                User.withUsername("locked@contexa.io").password("{noop}x").accountLocked(true).build()));

        for (String name : new String[]{"testuser", "disabled-user", "locked@contexa.io"}) {
            OneTimeToken token = service.generate(new GenerateOneTimeTokenRequest(name));

            assertThat(token.getUsername()).isEqualTo(name);
            assertThat(token.getTokenValue()).isEmpty();
        }
        verify(emailService, never()).sendHtmlMessage(anyString(), anyString(), anyString());
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM ctxa_one_time_tokens", Integer.class)).isZero();
    }

    @Test
    @DisplayName("generate should mail an open account of Contexa's table the store the sign-in reads knows")
    void generateMailsAnOpenAccount() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        service.setUserStore(() -> new InMemoryUserDetailsManager(
                User.withUsername("testuser").password("{noop}x").build()));

        OneTimeToken token = service.generate(new GenerateOneTimeTokenRequest("testuser"));

        assertThat(token.getTokenValue()).isNotEmpty();
        verify(emailService).sendHtmlMessage(eq("user@contexa.io"), anyString(), contains(token.getTokenValue()));
    }

    @Test
    @DisplayName("generate should mail nothing to a name a store that fails cannot vouch for, and answer all the same")
    void generateMailsNothingWhenTheStoreFails() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        service.setUserStore(() -> name -> {
            throw new IllegalStateException("The store is down");
        });

        OneTimeToken token = service.generate(new GenerateOneTimeTokenRequest("alice@contexa.io"));

        assertThat(token.getTokenValue()).isEmpty();
        verify(emailService, never()).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("generate should allow requested email only when it matches the registered user email")
    void generateTokenAllowsMatchingRequestedEmail() {
        when(emailService.isMailSenderConfigured()).thenReturn(true);

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

        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        assertThatThrownBy(() -> service.generate(new EmailGenerateOneTimeTokenRequest("testuser", "attacker@example.com")))
                .isInstanceOf(BadCredentialsException.class)
                .isInstanceOf(OneTimeTokenAddressRefusedException.class)
                .hasMessageContaining("Invalid one-time token delivery request");

        Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM ctxa_one_time_tokens", Integer.class);
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
        // Should still be stored in PostgreSQL database
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM ctxa_one_time_tokens WHERE token_value = ?", Integer.class, token.getTokenValue()
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
    @DisplayName("consume should return token and delete it from PostgreSQL database (one-time usage constraint)")
    void consumeTokenDeletesFromStore() {
        // Insert a token manually
        jdbcTemplate.update(
                "INSERT INTO ctxa_one_time_tokens(token_value, username, expires_at) VALUES(?, ?, ?)",
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

        // Verify it was deleted from PostgreSQL database (one-time usage check)
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM ctxa_one_time_tokens WHERE token_value = ?", Integer.class, "token-123"
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

    @Test
    @DisplayName("a code that requests present together is given to one of them only")
    void consumeGivesACodeToOneOfTheRequestsThatArriveTogether() throws Exception {
        jdbcTemplate.update(
                "INSERT INTO ctxa_one_time_tokens(token_value, username, expires_at) VALUES(?, ?, ?)",
                "token-shared", "testuser", Timestamp.from(Instant.now().plusSeconds(300))
        );
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );
        int requests = 16;
        ExecutorService executor = Executors.newFixedThreadPool(requests);
        CountDownLatch together = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        try {
            List<Future<?>> answers = new ArrayList<>();
            for (int i = 0; i < requests; i++) {
                answers.add(executor.submit(() -> {
                    together.await();
                    try {
                        service.consume(new OneTimeTokenAuthenticationToken("testuser", "token-shared"));
                        accepted.incrementAndGet();
                    } catch (InvalidOneTimeTokenException taken) {
                        refused.incrementAndGet();
                    }
                    return null;
                }));
            }
            together.countDown();
            for (Future<?> answer : answers) {
                answer.get(30, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
            service.destroy();
        }

        assertThat(accepted.get()).isEqualTo(1);
        assertThat(refused.get()).isEqualTo(requests - 1);
    }

    @Test
    @DisplayName("an expired code is refused and leaves the store")
    void consumeRefusesAnExpiredCode() {
        jdbcTemplate.update(
                "INSERT INTO ctxa_one_time_tokens(token_value, username, expires_at) VALUES(?, ?, ?)",
                "token-old", "testuser", Timestamp.from(Instant.now().minusSeconds(5))
        );
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                emailService, jdbcTemplate, transactionTemplate, authContextProperties, true
        );

        assertThatThrownBy(() -> service.consume(new OneTimeTokenAuthenticationToken("testuser", "token-old")))
                .isInstanceOf(InvalidOneTimeTokenException.class);
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM ctxa_one_time_tokens WHERE token_value = ?", Integer.class, "token-old")).isZero();
    }
}
