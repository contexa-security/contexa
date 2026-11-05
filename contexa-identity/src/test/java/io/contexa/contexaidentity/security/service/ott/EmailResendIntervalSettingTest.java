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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** {@code contexa.auth.mfa.email-resend-interval-seconds} and a store that gives no claim. */
class EmailResendIntervalSettingTest {

    private static final String SETTING = "contexa.auth.mfa.email-resend-interval-seconds";

    private final StepUpOptionsStore store = mock(StepUpOptionsStore.class);
    private final EmailService mail = mock(EmailService.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final Logger logger = (Logger) LoggerFactory.getLogger(EmailOneTimeTokenService.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

    private EmailOneTimeTokenService service;

    @BeforeEach
    void attachAppender() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stop() throws Exception {
        logger.detachAppender(logged);
        if (service != null) {
            service.destroy();
        }
    }

    private EmailOneTimeTokenService serviceWith(AuthContextProperties properties) {
        service = new EmailOneTimeTokenService(mail, jdbc, new TransactionTemplate(mock(PlatformTransactionManager.class)),
                properties, true, store);
        return service;
    }

    /** How long the first request of a user claims the address for. */
    private Duration holdWith(AuthContextProperties properties) {
        serviceWith(properties).generate(new GenerateOneTimeTokenRequest("alice@contexa.io"));
        ArgumentCaptor<Duration> hold = ArgumentCaptor.forClass(Duration.class);
        verify(store).claim(anyString(), hold.capture());
        return hold.getValue();
    }

    private static AuthContextProperties configured(int seconds) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getMfa().setEmailResendIntervalSeconds(seconds);
        return properties;
    }

    private long errorsNamingTheSetting() {
        return logged.list.stream()
                .filter(event -> event.getLevel() == Level.ERROR)
                .filter(event -> event.getFormattedMessage().contains(SETTING))
                .count();
    }

    @Test
    @DisplayName("without a setting the interval is 120 seconds and nothing is reported")
    void theDefaultIsTwoMinutes() {
        assertThat(holdWith(new AuthContextProperties())).isEqualTo(Duration.ofSeconds(120));
        assertThat(errorsNamingTheSetting()).isZero();
    }

    @Test
    @DisplayName("a positive setting is the interval")
    void aPositiveSettingIsTheInterval() {
        assertThat(holdWith(configured(45))).isEqualTo(Duration.ofSeconds(45));
        assertThat(errorsNamingTheSetting()).isZero();
    }

    /** No limit is not what a wrong value may mean: it would bring back the mail a password alone can send. */
    @ParameterizedTest
    @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
    @DisplayName("zero or less keeps the default, and says so at start, before any request")
    void zeroOrLessKeepsTheDefaultAndSaysSo(int seconds) {
        serviceWith(configured(seconds));
        assertThat(errorsNamingTheSetting()).as("when the service is built").isEqualTo(1);
        verifyNoInteractions(store);

        service.generate(new GenerateOneTimeTokenRequest("alice@contexa.io"));

        ArgumentCaptor<Duration> hold = ArgumentCaptor.forClass(Duration.class);
        verify(store).claim(anyString(), hold.capture());
        assertThat(hold.getValue()).isEqualTo(Duration.ofSeconds(120));
        assertThat(errorsNamingTheSetting()).as("once, not per request").isEqualTo(1);
    }

    /** What a store that cannot answer does (Redis down): what the claim guards does not happen. */
    @Test
    @DisplayName("a claim the store does not give mails nothing and makes no code")
    void aClaimNotGivenMailsNothing() {
        when(store.claim(anyString(), any(Duration.class))).thenReturn(false);

        OneTimeToken token = serviceWith(new AuthContextProperties())
                .generate(new GenerateOneTimeTokenRequest("alice@contexa.io"));

        assertThat(token.getTokenValue()).isEmpty();
        verify(mail, never()).sendHtmlMessage(anyString(), anyString(), anyString());
        verify(jdbc, never()).update(anyString(), any(Object[].class));
        verify(store, never()).release(anyString());
    }

    @Test
    @DisplayName("no address is written into the key of a claim, and the key stays short whatever the name")
    void theKeyHoldsNoAddress() {
        String longName = "x".repeat(10_000) + "@contexa.io";

        serviceWith(new AuthContextProperties()).generate(new GenerateOneTimeTokenRequest(longName));

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(store).claim(key.capture(), any(Duration.class));
        assertThat(key.getValue()).doesNotContain("contexa.io").hasSizeLessThan(100);
    }
}
