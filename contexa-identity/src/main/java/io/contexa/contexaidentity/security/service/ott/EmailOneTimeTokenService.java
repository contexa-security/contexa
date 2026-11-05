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
import io.contexa.contexacommon.jdbc.LibraryTableNames;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class EmailOneTimeTokenService implements OneTimeTokenService, DisposableBean {

    private static final String MAIL_SENT = "ott-mail-sent:";

    /**
     * What a request inside the resend interval gets: no code was made and nothing was mailed, so it has no value. It
     * carries the user, which is what the success handlers read, and the request is answered as a mailed one is.
     */
    private record NothingMailed(String username, Instant expiresAt) implements OneTimeToken {

        @Override
        public String getTokenValue() {
            return "";
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public Instant getExpiresAt() {
            return expiresAt;
        }
    }

    private final EmailService emailService;
    private final JdbcOneTimeTokenService delegate;
    private final TransactionTemplate transactionTemplate;
    private final AuthContextProperties authContextProperties;
    private final JdbcTemplate jdbcTemplate;
    private final boolean failOnEmailError;
    private final StepUpOptionsStore claims;
    private final Duration resendInterval;

    /** The resend interval is then this instance's own: a distributed deployment hands in the store it shares. */
    public EmailOneTimeTokenService(EmailService emailService,
                                    JdbcTemplate primaryJdbcTemplate,
                                    TransactionTemplate transactionTemplate,
                                    AuthContextProperties authContextProperties,
                                    boolean failOnEmailError) {
        this(emailService, primaryJdbcTemplate, transactionTemplate, authContextProperties, failOnEmailError,
                new InMemoryStepUpOptionsStore());
    }

    public EmailOneTimeTokenService(EmailService emailService,
                                    JdbcTemplate primaryJdbcTemplate,
                                    TransactionTemplate transactionTemplate,
                                    AuthContextProperties authContextProperties,
                                    boolean failOnEmailError,
                                    StepUpOptionsStore claims) {
        this.emailService = emailService;
        this.delegate = new JdbcOneTimeTokenService(LibraryTableNames.wrap(primaryJdbcTemplate));
        this.transactionTemplate = transactionTemplate;
        this.authContextProperties = authContextProperties;
        this.jdbcTemplate = primaryJdbcTemplate;
        this.failOnEmailError = failOnEmailError;
        this.claims = claims;
        this.resendInterval = resendInterval(authContextProperties.getMfa());
    }

    /** No limit is not what a wrong value may mean: it would give back the mail a password alone can send. */
    private static Duration resendInterval(MfaSettings settings) {
        int seconds = settings.getEmailResendIntervalSeconds();
        if (seconds > 0) {
            return Duration.ofSeconds(seconds);
        }
        log.error("contexa.auth.mfa.email-resend-interval-seconds must be positive but is {}: keeping {} seconds",
                seconds, MfaSettings.DEFAULT_EMAIL_RESEND_INTERVAL_SECONDS);
        return Duration.ofSeconds(MfaSettings.DEFAULT_EMAIL_RESEND_INTERVAL_SECONDS);
    }

    /**
     * The Spring Security service starts a scheduler thread (the clean-up of expired tokens, not a daemon) when it is built and stops it only in
     * {@code destroy()}. This service owns it, so it is stopped with this bean: otherwise the thread outlives a closed or a failed application
     * context and the JVM of the application does not end.
     */
    @Override
    public void destroy() throws Exception {
        delegate.destroy();
    }

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        String customEmail = null;
        if (request instanceof EmailGenerateOneTimeTokenRequest emailRequest) {
            customEmail = emailRequest.getEmail();
        }
        return generateAndSendVerificationCode(request.getUsername(), "Authentication Code (via generate)", customEmail);
    }

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose) {
        return generateAndSendVerificationCode(username, emailPurpose, null);
    }

    /**
     * Makes a code and mails it, once per address in the resend interval: asking for a code takes a password at most,
     * and the mailbox is someone's. The claim comes first, so requests at once find it held and leave no code behind.
     * A store that gives no claim mails nothing, as for a claim that is held.
     *
     * @return the code, or inside the interval a token of the user with an empty value: the code mailed before stays good
     */
    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose, String customEmail) {
        Assert.hasText(username, "Username cannot be empty");
        Assert.hasText(emailPurpose, "Email purpose cannot be empty");

        String to = resolveRecipientEmail(username, customEmail);
        String interval = intervalKey(to);
        if (!claims.claim(interval, resendInterval)) {
            log.debug("OTT email not sent, the resend interval is running: username={}", username);
            return new NothingMailed(username, Instant.now());
        }

        boolean mailed = false;
        try {
            OneTimeToken token = generateCode(username);
            mailed = mail(to, username, emailPurpose, token);
            return token;
        } finally {
            if (!mailed) {
                claims.release(interval);
            }
        }
    }

    private OneTimeToken generateCode(String username) {
        GenerateOneTimeTokenRequest internalTokenRequest = new GenerateOneTimeTokenRequest(username);
        AtomicReference<OneTimeToken> internalOneTimeToken = new AtomicReference<>();
        transactionTemplate.executeWithoutResult(status -> {
            internalOneTimeToken.set(delegate.generate(internalTokenRequest));
        });
        return internalOneTimeToken.get();
    }

    /** Whether the mail went out. */
    private boolean mail(String to, String username, String emailPurpose, OneTimeToken token) {
        long tokenValidityMinutes = Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()).toMinutes();

        String emailSubject = String.format("[Spring Security Platform] Your %s Verification Code", emailPurpose);
        String htmlBody = String.format(
                "<p>Hello %s,</p>" +
                        "<p>Your verification code for %s is: <strong style=\"font-size:1.2em; color:#3f51b5;\">%s</strong></p>" +
                        "<p>This code will expire in %d minutes.</p>" +
                        "<p>If you did not request this code, please ignore this email.</p>" +
                        "<p>Thank you.</p>",
                username, emailPurpose, token.getTokenValue(), tokenValidityMinutes
        );

        if (!emailService.isMailSenderConfigured()) {
            IllegalStateException failure = new IllegalStateException(
                    "Email sender is not configured. Please configure Spring mail properties.");
            if (failOnEmailError) {
                throw failure;
            }
            log.warn("OTT email sender is not configured; token was generated but email delivery was skipped for username={}",
                    username);
            return false;
        }

        try {
            emailService.sendHtmlMessage(to, emailSubject, htmlBody);
            return true;
        } catch (RuntimeException ex) {
            if (failOnEmailError) {
                throw ex;
            }
            log.warn("OTT email delivery failed; token was generated and retained for local verification. username={}, to={}",
                    username, to, ex);
            return false;
        }
    }

    /**
     * One key per mailbox, however the address is written (capitals, spaces, a name before it): a name that is no
     * account is mailed as an address, and each spelling would be a new key. The address itself stays out of the store.
     */
    private static String intervalKey(String to) {
        return MAIL_SENT + digest(mailbox(to).toLowerCase(Locale.ROOT));
    }

    private static String mailbox(String to) {
        String trimmed = to.trim();
        try {
            return new InternetAddress(trimmed).getAddress();
        } catch (AddressException notAnAddress) {
            return trimmed;
        }
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is not available", impossible);
        }
    }

    private String resolveRecipientEmail(String username, String requestedEmail) {
        String registeredEmail = lookupRegisteredEmail(username);
        if (requestedEmail != null && !requestedEmail.isBlank()) {
            String normalizedRequestedEmail = requestedEmail.trim();
            if (registeredEmail == null || registeredEmail.isBlank()
                    || !registeredEmail.trim().equalsIgnoreCase(normalizedRequestedEmail)) {
                log.warn("Rejected OTT email override for username: {}", username);
                throw new OneTimeTokenAddressRefusedException("Invalid one-time token delivery request");
            }
            return registeredEmail.trim();
        }

        if (registeredEmail != null && !registeredEmail.isBlank()) {
            return registeredEmail.trim();
        }

        return username;
    }

    private String lookupRegisteredEmail(String username) {
        try {
            return jdbcTemplate.queryForObject("SELECT email FROM ctxa_users WHERE username = ?", String.class, username);
        } catch (Exception e) {
            log.warn("Failed to find user email for username: {}", username, e);
            return null;
        }
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        OneTimeToken internalTokenFromStore = delegate.consume(authenticationToken);
        if (internalTokenFromStore == null) {
            throw new InvalidOneTimeTokenException("Invalid or expired code. Not found in store.");
        }
        // The interval waits because the last code is still good. A used one leaves the user without a code, and only
        // who reads the mail could use it: a step-up right after a sign-in gets its code at once.
        claims.release(intervalKey(resolveRecipientEmail(internalTokenFromStore.getUsername(), null)));
        return internalTokenFromStore;
    }
}
