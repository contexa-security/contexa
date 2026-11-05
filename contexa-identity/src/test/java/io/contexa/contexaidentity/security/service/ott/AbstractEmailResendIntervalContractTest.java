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
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcTransactionManager;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * One address gets one mail of a code in the resend interval, the same in memory and in Redis. A password alone was
 * enough to ask for a code, and each request mailed one to the victim. Every case takes a user of its own, so the Redis
 * case flushes nothing on the server it runs against.
 */
abstract class AbstractEmailResendIntervalContractTest {

    private static final int REQUESTS = 20;

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    /** Mail that is counted, and that can be broken or missing as a mail server can be. */
    static final class RecordingMail extends EmailService {

        final List<String> sentTo = new CopyOnWriteArrayList<>();
        final AtomicBoolean broken = new AtomicBoolean();
        final AtomicBoolean configured = new AtomicBoolean(true);

        RecordingMail() {
            super(null);
        }

        @Override
        public boolean isMailSenderConfigured() {
            return configured.get();
        }

        @Override
        public void sendHtmlMessage(String to, String subject, String htmlBody) {
            if (broken.get()) {
                throw new IllegalStateException("The mail server is down");
            }
            sentTo.add(to);
        }
    }

    /** The store of the codes, which can be down while the store of the claims is not. */
    private static final class BreakableTransactions extends TransactionTemplate {

        final AtomicBoolean broken = new AtomicBoolean();

        BreakableTransactions() {
            super(new JdbcTransactionManager(database.dataSource()));
        }

        @Override
        public <T> T execute(TransactionCallback<T> action) {
            if (broken.get()) {
                throw new TransactionSystemException("The database is down");
            }
            return super.execute(action);
        }
    }

    protected final RecordingMail mail = new RecordingMail();
    protected final String username = "user-" + UUID.randomUUID();
    protected final String address = username + "@contexa.io";

    private final BreakableTransactions transactions = new BreakableTransactions();
    private final List<EmailOneTimeTokenService> services = new ArrayList<>();

    protected abstract StepUpOptionsStore store();

    @BeforeAll
    static void openDatabase() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        jdbc.execute("CREATE TABLE ctxa_one_time_tokens (token_value VARCHAR(256) NOT NULL, "
                + "username VARCHAR(256) NOT NULL, expires_at TIMESTAMP NOT NULL, PRIMARY KEY (token_value))");
        jdbc.execute("CREATE TABLE ctxa_users (username VARCHAR(256) NOT NULL, email VARCHAR(256) NOT NULL, "
                + "PRIMARY KEY (username))");
    }

    @AfterAll
    static void closeDatabase() {
        database.close();
    }

    @BeforeEach
    void registerTheUser() {
        jdbc.update("INSERT INTO ctxa_users(username, email) VALUES(?, ?)", username, address);
    }

    @AfterEach
    void stopTheServices() throws Exception {
        for (EmailOneTimeTokenService service : services) {
            service.destroy();
        }
    }

    protected EmailOneTimeTokenService service(int intervalSeconds, boolean failOnEmailError) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getMfa().setEmailResendIntervalSeconds(intervalSeconds);
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                mail, jdbc, transactions, properties, failOnEmailError, store());
        services.add(service);
        return service;
    }

    private EmailOneTimeTokenService service() {
        return service(120, true);
    }

    private static OneTimeToken ask(EmailOneTimeTokenService service, String name) {
        return service.generate(new GenerateOneTimeTokenRequest(name));
    }

    private int codesOf(String name) {
        Integer codes = jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_one_time_tokens WHERE username = ?",
                Integer.class, name);
        return codes == null ? 0 : codes;
    }

    /** Asks from every caller at once and gives what each one got back. */
    protected List<OneTimeToken> askAtOnce(List<EmailOneTimeTokenService> nodes) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService callers = Executors.newFixedThreadPool(REQUESTS);
        try {
            List<Future<OneTimeToken>> answers = new ArrayList<>();
            for (int i = 0; i < REQUESTS; i++) {
                EmailOneTimeTokenService node = nodes.get(i % nodes.size());
                answers.add(callers.submit(() -> {
                    start.await();
                    return ask(node, username);
                }));
            }
            start.countDown();
            List<OneTimeToken> tokens = new ArrayList<>();
            for (Future<OneTimeToken> answer : answers) {
                tokens.add(answer.get());
            }
            return tokens;
        } finally {
            callers.shutdownNow();
        }
    }

    protected void assertOneMailOutOf(List<OneTimeToken> tokens) {
        assertThat(mail.sentTo).containsExactly(address);
        assertThat(tokens).hasSize(REQUESTS).allSatisfy(token -> assertThat(token.getUsername()).isEqualTo(username));
        assertThat(tokens).filteredOn(token -> !token.getTokenValue().isEmpty()).as("codes handed back").hasSize(1);
        assertThat(codesOf(username)).as("codes stored").isEqualTo(1);
    }

    @Test
    @DisplayName("twenty requests one after the other mail once and store one code")
    void requestsInARowMailOnce() {
        EmailOneTimeTokenService service = service();
        List<OneTimeToken> tokens = new ArrayList<>();

        for (int i = 0; i < REQUESTS; i++) {
            tokens.add(ask(service, username));
        }

        assertOneMailOutOf(tokens);
    }

    @RepeatedTest(25)
    @DisplayName("twenty requests at once mail once and store one code")
    void requestsAtOnceMailOnce() throws Exception {
        assertOneMailOutOf(askAtOnce(List.of(service())));
    }

    @Test
    @DisplayName("the code mailed before stays good after requests the interval refused")
    void theCodeMailedBeforeStaysGood() {
        EmailOneTimeTokenService service = service();
        OneTimeToken mailed = ask(service, username);
        ask(service, username);
        ask(service, username);

        OneTimeToken used = service.consume(new OneTimeTokenAuthenticationToken(mailed.getTokenValue()));

        assertThat(used.getUsername()).isEqualTo(username);
    }

    @Test
    @DisplayName("a refused request gets no value, and its token opens nothing")
    void aRefusedRequestGetsNoCode() {
        EmailOneTimeTokenService service = service();
        ask(service, username);

        OneTimeToken refused = ask(service, username);

        assertThat(refused.getUsername()).isEqualTo(username);
        assertThat(refused.getTokenValue()).isEmpty();
        assertThatThrownBy(() -> service.consume(new OneTimeTokenAuthenticationToken(refused.getTokenValue())))
                .isInstanceOf(InvalidOneTimeTokenException.class);
    }

    @Test
    @DisplayName("every spelling of one address is one address, registered as a user's or typed in as a name")
    void everySpellingIsOneAddress() {
        EmailOneTimeTokenService service = service();

        ask(service, username);
        ask(service, address);
        ask(service, address.toUpperCase(Locale.ROOT));
        ask(service, "  " + address + "  ");
        ask(service, "Someone Else <" + address + ">");

        assertThat(mail.sentTo).containsExactly(address);
    }

    @Test
    @DisplayName("two addresses are apart")
    void twoAddressesAreApart() {
        EmailOneTimeTokenService service = service();
        String other = "other-" + address;

        ask(service, username);
        ask(service, other);

        assertThat(mail.sentTo).containsExactly(address, other);
    }

    @Test
    @DisplayName("a mail that failed binds nobody: the error stands and the next request mails")
    void aFailedMailBindsNobody() {
        EmailOneTimeTokenService service = service();
        mail.broken.set(true);
        assertThatThrownBy(() -> ask(service, username)).hasMessageContaining("The mail server is down");

        mail.broken.set(false);
        OneTimeToken retried = ask(service, username);

        assertThat(retried.getTokenValue()).isNotEmpty();
        assertThat(mail.sentTo).containsExactly(address);
        assertThat(ask(service, username).getTokenValue()).as("a mail that went out starts the interval").isEmpty();
    }

    @Test
    @DisplayName("a mail that failed quietly binds nobody either")
    void aQuietlyFailedMailBindsNobody() {
        EmailOneTimeTokenService service = service(120, false);
        mail.broken.set(true);
        assertThat(ask(service, username).getTokenValue()).as("kept for local verification").isNotEmpty();

        mail.broken.set(false);
        ask(service, username);

        assertThat(mail.sentTo).containsExactly(address);
    }

    @Test
    @DisplayName("without a mail sender nothing went out, so nothing waits, with or without the error")
    void noSenderBindsNobody() {
        EmailOneTimeTokenService strict = service(120, true);
        EmailOneTimeTokenService lenient = service(120, false);
        mail.configured.set(false);

        assertThatThrownBy(() -> ask(strict, username)).hasMessageContaining("Email sender is not configured");
        assertThat(ask(lenient, username).getTokenValue()).isNotEmpty();
        assertThat(ask(lenient, username).getTokenValue()).isNotEmpty();

        mail.configured.set(true);
        ask(strict, username);

        assertThat(mail.sentTo).containsExactly(address);
    }

    @Test
    @DisplayName("a code that could not be stored binds nobody")
    void aCodeNotStoredBindsNobody() {
        EmailOneTimeTokenService service = service();
        transactions.broken.set(true);
        assertThatThrownBy(() -> ask(service, username)).hasMessageContaining("The database is down");

        transactions.broken.set(false);
        ask(service, username);

        assertThat(mail.sentTo).containsExactly(address);
    }

    @Test
    @DisplayName("a request refused for its address counts for nothing")
    void aRefusedAddressCountsForNothing() {
        EmailOneTimeTokenService service = service();
        assertThatThrownBy(() -> service.generate(new EmailGenerateOneTimeTokenRequest(username, "attacker@example.com")))
                .isInstanceOf(OneTimeTokenAddressRefusedException.class);

        ask(service, username);

        assertThat(mail.sentTo).containsExactly(address);
    }

    @Test
    @DisplayName("past the interval the next request mails again")
    void pastTheIntervalAMailGoesOut() {
        EmailOneTimeTokenService service = service(1, true);
        ask(service, username);
        assertThat(ask(service, username).getTokenValue()).as("inside the interval").isEmpty();

        Awaitility.await().atMost(Duration.ofSeconds(4)).pollInterval(Duration.ofMillis(100))
                .until(() -> !ask(service, username).getTokenValue().isEmpty());

        assertThat(mail.sentTo).containsExactly(address, address);
    }

    @Test
    @DisplayName("a used code frees the address: the wait is there because the last code is still good")
    void aUsedCodeFreesTheAddress() {
        EmailOneTimeTokenService service = service();
        OneTimeToken mailed = ask(service, username);

        service.consume(new OneTimeTokenAuthenticationToken(mailed.getTokenValue()));
        OneTimeToken next = ask(service, username);

        assertThat(next.getTokenValue()).isNotEmpty();
        assertThat(mail.sentTo).containsExactly(address, address);
    }

    @Test
    @DisplayName("a wrong code frees nothing: only who reads the mail ends the wait early")
    void aWrongCodeFreesNothing() {
        EmailOneTimeTokenService service = service();
        ask(service, username);

        assertThatThrownBy(() -> service.consume(new OneTimeTokenAuthenticationToken("not-the-code")))
                .isInstanceOf(InvalidOneTimeTokenException.class);
        ask(service, username);

        assertThat(mail.sentTo).containsExactly(address);
    }
}
