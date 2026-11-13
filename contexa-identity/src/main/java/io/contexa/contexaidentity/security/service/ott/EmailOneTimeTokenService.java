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
import io.contexa.contexacommon.security.LocalAccountStatusChecker;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

@Slf4j
public class EmailOneTimeTokenService implements OneTimeTokenService, DisposableBean {

    private static final String MAIL_SENT = "ott-mail-sent:";

    /**
     * What a request inside the resend interval or for a name of no account gets: no code was made and nothing was mailed,
     * so it has no value. It carries the user, which is what the success handlers read, and the request is answered as a
     * mailed one is.
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
    private volatile Supplier<UserDetailsService> userStore = () -> null;
    /** Development and tests: the code is written to the log too, and a sign-in does not wait on a mail server. */
    private volatile boolean codeToConsole;

    public void setCodeToConsole(boolean codeToConsole) {
        this.codeToConsole = codeToConsole;
    }

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

    /**
     * The store the sign-in reads, which is the application's where the application keeps its sign-in: its users are in no
     * table of Contexa's, and their name is the address they are mailed at. Where Contexa owns the sign-in it is Contexa's
     * own. Read when a code is asked for.
     */
    public void setUserStore(Supplier<UserDetailsService> userStore) {
        this.userStore = userStore != null ? userStore : () -> null;
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
        return generateAndSendVerificationCode(request.getUsername(), "Authentication Code (via generate)", customEmail,
                request instanceof MfaCodeRequest);
    }

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose) {
        return generateAndSendVerificationCode(username, emailPurpose, null);
    }

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose, String customEmail) {
        return generateAndSendVerificationCode(username, emailPurpose, customEmail, false);
    }

    /**
     * Makes a code and mails it, once per address in the resend interval: asking for a code takes a password at most,
     * and the mailbox is someone's. The claim comes first, so requests at once find it held and leave no code behind.
     * A store that gives no claim mails nothing, as for a claim that is held. A name of no account is mailed nothing:
     * before a sign-in the name is what a form says, so the code would go to any address a stranger typed, and it would
     * sign in to nothing. A locked or disabled account is mailed nothing either: the code would sign in to nothing, and the
     * answer is the one a name of no account gets, so asking tells nothing of the account's state.
     *
     * @param mfaCode a code of an MFA step, six digits kept under the user ({@link MfaCodes}); otherwise a long code
     * @return the code, or a token of the user with an empty value: inside the interval, where the code mailed before stays
     * good, for a name of no account, and for an account the sign-in refuses
     */
    private OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose, String customEmail,
                                                         boolean mfaCode) {
        Assert.hasText(username, "Username cannot be empty");
        Assert.hasText(emailPurpose, "Email purpose cannot be empty");

        String registeredEmail = lookupRegisteredEmail(username);
        refuseAnotherAddress(username, registeredEmail, customEmail);
        Standing standing = standing(username);
        if (standing == Standing.REFUSED) {
            log.debug("OTT email not sent, the account does not sign in: username={}", username);
            return new NothingMailed(username, Instant.now());
        }
        if (!StringUtils.hasText(registeredEmail) && standing != Standing.OPEN) {
            log.debug("OTT email not sent, the name is no account: username={}", username);
            return new NothingMailed(username, Instant.now());
        }

        String to = recipient(username, registeredEmail);
        String interval = intervalKey(to);
        if (!claims.claim(interval, resendInterval)) {
            log.debug("OTT email not sent, the resend interval is running: username={}", username);
            return new NothingMailed(username, Instant.now());
        }

        boolean mailed = false;
        try {
            OneTimeToken token = mfaCode ? generateMfaCode(username) : generateCode(username);
            mailed = mail(to, username, emailPurpose, token);
            return token;
        } finally {
            if (!mailed) {
                claims.release(interval);
            }
        }
    }

    /**
     * A six-digit code stored under the user. Two users may draw the same digits, since each is kept under its user; the
     * same user drawing the digits of a code still good is the one collision, and another draw follows.
     */
    private OneTimeToken generateMfaCode(String username) {
        Instant expiresAt = Instant.now().plusSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds());
        for (int draw = 0; draw < 5; draw++) {
            String code = MfaCodes.newCode();
            try {
                transactionTemplate.executeWithoutResult(status -> jdbcTemplate.update(
                        "INSERT INTO ctxa_one_time_tokens (token_value, username, expires_at) VALUES (?, ?, ?)",
                        MfaCodes.keyOf(username, code), username, Timestamp.from(expiresAt)));
                return new DefaultOneTimeToken(code, username, expiresAt);
            } catch (DuplicateKeyException sameDigits) {
                log.debug("An MFA code of the same digits is still good for the user; another is drawn: username={}",
                        username);
            }
        }
        throw new IllegalStateException("No free MFA code could be drawn for the user");
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
                HtmlUtils.htmlEscape(username), emailPurpose, token.getTokenValue(), tokenValidityMinutes
        );

        if (codeToConsole) {
            log.warn("[OTT] Sign-in code for {} <{}>: {} (valid {} minutes). It is written here because one-time codes go "
                            + "to the log in development and tests (contexa.auth.ott.code-to-console); a production start "
                            + "mails them only.",
                    username, to, token.getTokenValue(), tokenValidityMinutes);
        }

        if (!emailService.isMailSenderConfigured()) {
            if (codeToConsole) {
                return true;
            }
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
            if (codeToConsole) {
                // the code in the log above finishes the sign-in: a mail server that is down or absent stops nothing
                log.warn("[OTT] The code mail to {} was not sent ({}); the code written above stands for this sign-in",
                        to, ex.toString());
                return true;
            }
            if (failOnEmailError) {
                throw ex;
            }
            log.warn("OTT email delivery failed; token was generated and retained for local verification. username={}, to={}",
                    username, to, ex);
            return false;
        }
    }

    /**
     * One key per mailbox, however the address is written (capitals, spaces, a name before it): the name of an account of
     * the application's is mailed as an address, and each spelling would be a new key. The address itself stays out of the
     * store.
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

    private static void refuseAnotherAddress(String username, String registeredEmail, String requestedEmail) {
        if (requestedEmail == null || requestedEmail.isBlank()) {
            return;
        }
        if (!StringUtils.hasText(registeredEmail) || !registeredEmail.trim().equalsIgnoreCase(requestedEmail.trim())) {
            log.warn("Rejected OTT email override for username: {}", username);
            throw new OneTimeTokenAddressRefusedException("Invalid one-time token delivery request");
        }
    }

    /** The registered address, or the name of an account the users table does not hold. */
    private static String recipient(String username, String registeredEmail) {
        return StringUtils.hasText(registeredEmail) ? registeredEmail.trim() : username;
    }

    /** What the store the sign-in reads says of a name. */
    private enum Standing {
        /** An account that may sign in. */
        OPEN,
        /** An account the sign-in refuses: locked, disabled, expired, or one that signs in elsewhere only. */
        REFUSED,
        /** No store, no account of the name, or a store that cannot say. */
        UNKNOWN
    }

    /**
     * What the store the sign-in reads says of the name. A code signs in to no account the store refuses, so none is made
     * for it; a store that cannot say leaves a name of no registered address unmailed.
     */
    private Standing standing(String username) {
        try {
            UserDetailsService store = userStore.get();
            UserDetails account = store != null ? store.loadUserByUsername(username) : null;
            if (account == null) {
                return Standing.UNKNOWN;
            }
            LocalAccountStatusChecker.checkBeforeCredentials(account);
            return Standing.OPEN;
        } catch (UsernameNotFoundException noAccount) {
            return Standing.UNKNOWN;
        } catch (AuthenticationException refused) {
            return Standing.REFUSED;
        } catch (RuntimeException e) {
            log.error("The user store could not say whether a name is an account: username={}", username, e);
            return Standing.UNKNOWN;
        }
    }

    private String lookupRegisteredEmail(String username) {
        try {
            return jdbcTemplate.queryForObject("SELECT email FROM ctxa_users WHERE username = ?", String.class, username);
        } catch (EmptyResultDataAccessException noRow) {
            // Anyone may ask in any name: reporting each one would hand a stranger the size of the log.
            return null;
        } catch (Exception e) {
            log.warn("Failed to find user email for username: {}", username, e);
            return null;
        }
    }

    /**
     * Takes the code a person entered. A six-digit code of an MFA step is looked up under the user of the step, which the
     * authentication carries as its principal: without the user it is not found at all, so the digits alone reach no code
     * of anyone. A long code is looked up as it is, and is held to the user too when the step names one.
     */
    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        String entered = authenticationToken.getTokenValue();
        String stepUser = authenticationToken.getPrincipal() instanceof String user && StringUtils.hasText(user) ? user : null;
        OneTimeToken internalTokenFromStore;
        if (MfaCodes.isCode(entered)) {
            internalTokenFromStore = stepUser == null ? null : consumeOnce(MfaCodes.keyOf(stepUser, entered));
        } else {
            internalTokenFromStore = consumeOnce(entered);
            if (internalTokenFromStore != null && stepUser != null && !stepUser.equals(internalTokenFromStore.getUsername())) {
                internalTokenFromStore = null;
            }
        }
        if (internalTokenFromStore == null) {
            throw new InvalidOneTimeTokenException("Invalid or expired code. Not found in store.");
        }
        // The interval waits because the last code is still good. A used one leaves the user without a code, and only
        // who reads the mail could use it: a step-up right after a sign-in gets its code at once.
        String username = internalTokenFromStore.getUsername();
        claims.release(intervalKey(recipient(username, lookupRegisteredEmail(username))));
        return internalTokenFromStore;
    }

    /**
     * Takes the code out of the store for one request only. The Spring Security service reads the code and then deletes
     * it without asking whether the delete removed anything, so requests that arrive together all read it and all pass.
     * Here the delete decides: the database lets one of them remove the row, and only that one has the code.
     *
     * @return the code, or {@code null} for a code that is unknown, was taken by another request, or has expired
     */
    private OneTimeToken consumeOnce(String tokenValue) {
        if (!StringUtils.hasText(tokenValue)) {
            return null;
        }
        List<OneTimeToken> stored = jdbcTemplate.query(
                "SELECT token_value, username, expires_at FROM ctxa_one_time_tokens WHERE token_value = ?",
                (row, rowNumber) -> new DefaultOneTimeToken(row.getString("token_value"), row.getString("username"),
                        row.getTimestamp("expires_at").toInstant()),
                tokenValue);
        if (stored.isEmpty()) {
            return null;
        }
        int removed = jdbcTemplate.update("DELETE FROM ctxa_one_time_tokens WHERE token_value = ?", tokenValue);
        if (removed != 1) {
            return null;
        }
        OneTimeToken code = stored.get(0);
        return code.getExpiresAt().isBefore(Instant.now()) ? null : code;
    }
}
