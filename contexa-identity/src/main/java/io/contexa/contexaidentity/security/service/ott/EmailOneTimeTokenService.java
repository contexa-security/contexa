package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.*;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import javax.sql.DataSource;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

@Service
@Slf4j
public class EmailOneTimeTokenService implements OneTimeTokenService {

    private final JdbcOneTimeTokenService delegate;
    private final EmailService emailService;
    private final AuthContextProperties authContextProperties;

    @Value("${app.url.base:http://localhost:8080}")
    private String baseUrl;

    public EmailOneTimeTokenService(EmailService emailService,
                                    JdbcTemplate primaryJdbcTemplate,
                                    AuthContextProperties authContextProperties) {
        this.delegate = new JdbcOneTimeTokenService(primaryJdbcTemplate);
        this.emailService = emailService;
        this.authContextProperties = authContextProperties;
//        this.delegate.setTokenValidity(Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()));
        log.info("EmailOneTimeTokenService initialized. OTT Token Validity: {} seconds (from MfaSettings).",
                authContextProperties.getMfa().getOtpTokenValiditySeconds());
    }

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        return generateAndSendVerificationCode(request.getUsername(), "Authentication Code (via generate)");
    }

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose) {
        Assert.hasText(username, "Username cannot be empty");
        Assert.hasText(emailPurpose, "Email purpose cannot be empty");

        SecureRandom random = new SecureRandom();
        String numericCode = String.format("%06d", random.nextInt(1_000_000));

        GenerateOneTimeTokenRequest internalTokenRequest = new GenerateOneTimeTokenRequest(username);
        OneTimeToken internalOneTimeToken = delegate.generate(internalTokenRequest);

        log.info("Saved mapping: User-facing code '{}' -> Internal token '{}' for user '{}'. Validity: {}s",
                numericCode, internalOneTimeToken.getTokenValue(), username, authContextProperties.getMfa().getOtpTokenValiditySeconds());

        long tokenValidityMinutes = Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()).toMinutes();

        String emailSubject = String.format("[Spring Security Platform] Your %s Verification Code", emailPurpose);
        String htmlBody = String.format(
                "<p>Hello %s,</p>" +
                        "<p>Your verification code for %s is: <strong style=\"font-size:1.2em; color:#3f51b5;\">%s</strong></p>" +
                        "<p>This code will expire in %d minutes.</p>" +
                        "<p>If you did not request this code, please ignore this email.</p>" +
                        "<p>Thank you.</p>",
                username, emailPurpose, numericCode, tokenValidityMinutes
        );

        emailService.sendHtmlMessage(username, emailSubject, htmlBody);
        log.info("Verification code ({}) for {} sent to {}. Token validity display: {} minutes.",
                numericCode, emailPurpose, username, tokenValidityMinutes);

        return internalOneTimeToken;
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