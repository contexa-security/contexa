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

    private final JdbcOneTimeTokenService delegate;
    private final TransactionTemplate transactionTemplate;
    private final AuthContextProperties authContextProperties;

    public EmailOneTimeTokenService(EmailService emailService,
                                    JdbcTemplate primaryJdbcTemplate,
                                    TransactionTemplate transactionTemplate,
                                    AuthContextProperties authContextProperties) {
        this.delegate = new JdbcOneTimeTokenService(primaryJdbcTemplate);
        this.transactionTemplate = transactionTemplate;
        this.authContextProperties = authContextProperties;
    }

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        return generateAndSendVerificationCode(request.getUsername(), "Authentication Code (via generate)");
    }

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose) {
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