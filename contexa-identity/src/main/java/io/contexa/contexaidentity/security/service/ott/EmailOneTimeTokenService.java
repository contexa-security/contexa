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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class EmailOneTimeTokenService implements OneTimeTokenService {

    private final EmailService emailService;
    private final JdbcOneTimeTokenService delegate;
    private final TransactionTemplate transactionTemplate;
    private final AuthContextProperties authContextProperties;
    private final JdbcTemplate jdbcTemplate;

    public EmailOneTimeTokenService(EmailService emailService,
                                    JdbcTemplate primaryJdbcTemplate,
                                    TransactionTemplate transactionTemplate,
                                    AuthContextProperties authContextProperties) {
        this.emailService = emailService;
        this.delegate = new JdbcOneTimeTokenService(primaryJdbcTemplate);
        this.transactionTemplate = transactionTemplate;
        this.authContextProperties = authContextProperties;
        this.jdbcTemplate = primaryJdbcTemplate;
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

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose, String customEmail) {
        Assert.hasText(username, "Username cannot be empty");
        Assert.hasText(emailPurpose, "Email purpose cannot be empty");

        GenerateOneTimeTokenRequest internalTokenRequest = new GenerateOneTimeTokenRequest(username);
        AtomicReference<OneTimeToken> internalOneTimeToken = new AtomicReference<>();
        transactionTemplate.executeWithoutResult(status -> {
            internalOneTimeToken.set(delegate.generate(internalTokenRequest));
        });

        long tokenValidityMinutes = Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()).toMinutes();

        String emailSubject = String.format("[Spring Security Platform] Your %s Verification Code", emailPurpose);
        String htmlBody = String.format(
                "<p>Hello %s,</p>" +
                        "<p>Your verification code for %s is: <strong style=\"font-size:1.2em; color:#3f51b5;\">%s</strong></p>" +
                        "<p>This code will expire in %d minutes.</p>" +
                        "<p>If you did not request this code, please ignore this email.</p>" +
                        "<p>Thank you.</p>",
                username, emailPurpose, internalOneTimeToken.get().getTokenValue(), tokenValidityMinutes
        );

        String to = customEmail;
        if (to == null || to.isBlank()) {
            try {
                to = jdbcTemplate.queryForObject("SELECT email FROM users WHERE username = ?", String.class, username);
            } catch (Exception e) {
                log.warn("Failed to find user email for username: {}", username, e);
            }
        }

        if (to == null || to.isBlank()) {
            to = username;
        }

        if (!emailService.isMailSenderConfigured()) {
            throw new IllegalStateException("Email sender is not configured. Please configure Spring mail properties.");
        }

        emailService.sendHtmlMessage(to, emailSubject, htmlBody);

        return internalOneTimeToken.get();
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        OneTimeToken internalTokenFromStore = delegate.consume(authenticationToken);
        if (internalTokenFromStore == null) {
            throw new InvalidOneTimeTokenException("Invalid or expired code. Not found in store.");
        }
        return internalTokenFromStore;
    }
}
