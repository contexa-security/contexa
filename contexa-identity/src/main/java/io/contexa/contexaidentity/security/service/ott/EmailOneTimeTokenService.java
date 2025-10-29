package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ott.*;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

@Service
@Slf4j
public class EmailOneTimeTokenService implements OneTimeTokenService {

    private final InMemoryOneTimeTokenService delegate;
    private final EmailService emailService;
    private final CodeStore codeStore;
    private final AuthContextProperties authContextProperties;

    @Value("${app.url.base:http://localhost:8080}")
    private String baseUrl;

    public EmailOneTimeTokenService(EmailService emailService,
                                    CodeStore codeStore,
                                    AuthContextProperties authContextProperties) {
        this.delegate = new InMemoryOneTimeTokenService();
        this.emailService = emailService;
        this.codeStore = codeStore;
        this.authContextProperties = authContextProperties;
//        this.delegate.setTokenValidity(Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()));
        log.info("EmailOneTimeTokenService initialized. OTT Token Validity: {} seconds (from MfaSettings).",
                authContextProperties.getMfa().getOtpTokenValiditySeconds());
    }

    public OneTimeToken generateAndSendVerificationCode(String username, String emailPurpose) {
        Assert.hasText(username, "Username cannot be empty");
        Assert.hasText(emailPurpose, "Email purpose cannot be empty");

        SecureRandom random = new SecureRandom();
        String numericCode = String.format("%06d", random.nextInt(1_000_000));

        GenerateOneTimeTokenRequest internalTokenRequest = new GenerateOneTimeTokenRequest(username);
        OneTimeToken internalOneTimeToken = delegate.generate(internalTokenRequest);

        codeStore.save(numericCode, internalOneTimeToken, Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()));
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

    public OneTimeToken generateAndSendMagicLink(GenerateOneTimeTokenRequest request, String loginProcessingPath, String emailPurpose) {
        Assert.notNull(request, "GenerateOneTimeTokenRequest cannot be null");
        Assert.hasText(request.getUsername(), "Username in request cannot be empty");
        Assert.hasText(loginProcessingPath, "loginProcessingPath cannot be empty");
        Assert.hasText(emailPurpose, "emailPurpose cannot be empty");

        OneTimeToken internalOneTimeToken = delegate.generate(request);
        String magicLinkExternalCode = UUID.randomUUID().toString();
        codeStore.save(magicLinkExternalCode, internalOneTimeToken, Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()));

        String loginLink = UriComponentsBuilder.fromUriString(baseUrl)
                .path(loginProcessingPath)
                .queryParam("code", URLEncoder.encode(magicLinkExternalCode, StandardCharsets.UTF_8))
                .build(true)
                .toUriString();

        String emailSubject = String.format("[Spring Security Platform] %s - Login Link", emailPurpose);
        long tokenValidityMinutes = Duration.ofSeconds(authContextProperties.getMfa().getOtpTokenValiditySeconds()).toMinutes();

        String htmlBody = String.format(
                "<p>Hello %s,</p>" +
                        "<p>Please click the link below to log in securely for %s:</p>" +
                        "<p><a href=\"%s\" style=\"display:inline-block;padding:10px 20px;" +
                        "background-color:#2196f3;color:white;text-decoration:none;" +
                        "border-radius:4px;\">Log In Securely</a></p>" +
                        "<p>This link will expire in %d minutes.</p>" +
                        "<p>If you did not request this, please ignore this email.</p>" +
                        "<p>Thank you.</p>",
                request.getUsername(), emailPurpose, loginLink, tokenValidityMinutes
        );

        emailService.sendHtmlMessage(request.getUsername(), emailSubject, htmlBody);
        log.info("Magic link for {} sent to {} for path {}. ExternalLinkCode: {}. Token validity display: {} minutes.",
                emailPurpose, request.getUsername(), loginProcessingPath, magicLinkExternalCode, tokenValidityMinutes);
        return internalOneTimeToken;
    }


    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        // 이 메서드는 Spring Security의 GenerateOneTimeTokenFilter에 의해 호출될 수 있습니다.
        // MFA 흐름에서는 주로 MfaApiController를 통해 generateAndSendVerificationCode를 호출하므로,
        // 이 메서드는 단일 OTT (예: /loginOtt -> /login/ott/generate) 시나리오에 더 가깝습니다.
        // 현재 EmailOneTimeTokenService의 생성자에서 토큰 유효기간을 설정하므로, 여기서 별도로 설정할 필요는 없습니다.
        log.debug("Generic OneTimeTokenService.generate() called for user: {}. Purpose: {}", request.getUsername());

        // 요청 목적(purpose)에 따라 다른 로직을 수행할 수 있으나, 현재는 구분 없이 6자리 코드를 생성하는
        // generateAndSendVerificationCode를 호출하거나, 매직링크를 생성할 수 있습니다.
        // PlatformSecurityConfig에서 단일 OTT 와 MFA OTT를 위한 GenerateOneTimeTokenFilter를 각각 설정하고
        // 다른 successHandler를 연결하는 것이 더 명확합니다.
        // 여기서는 'MFA Authentication' 목적을 가정하고 6자리 코드를 생성합니다.
        // 만약 단일 OTT 용도로도 이 generate()가 사용된다면,
        // 호출 경로(URL)나 request 객체 내의 다른 정보를 통해 분기해야 합니다.
        // 현재 제공된 `OneTimeTokenCreationSuccessHandler`는 MFA와 단일 OTT 모두 처리하려고 시도하고 있습니다.
        return generateAndSendVerificationCode(request.getUsername(), "Authentication Code (via generate)");
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        String userProvidedCode = authenticationToken.getTokenValue();
        String username = authenticationToken.getName();

        log.debug("Attempting to consume user-provided code: '{}' for user: '{}'", userProvidedCode, username);

        OneTimeToken internalTokenFromStore = codeStore.consume(userProvidedCode);

        if (internalTokenFromStore == null) {
            log.warn("No internal token found in CodeStore for user-provided code: '{}' (user: '{}').", userProvidedCode, username);
            throw new InvalidOneTimeTokenException("Invalid or expired code. Not found in store.");
        }

        if (!internalTokenFromStore.getUsername().equals(username)) {
            log.warn("Username mismatch for user-provided code '{}'. Expected: '{}', Actual in stored token: '{}'. This is a security concern.",
                    userProvidedCode, username, internalTokenFromStore.getUsername());
            throw new InvalidOneTimeTokenException("Username mismatch for the provided code.");
        }

        try {
            OneTimeTokenAuthenticationToken internalAuthToken =
                    new OneTimeTokenAuthenticationToken(internalTokenFromStore.getUsername(), internalTokenFromStore.getTokenValue());
            OneTimeToken consumedDelegateToken = delegate.consume(internalAuthToken);

            log.info("Successfully consumed user-provided code {} (via internal token {}) for user {}",
                    userProvidedCode, internalTokenFromStore.getTokenValue(), username);
            return consumedDelegateToken;
        } catch (InvalidOneTimeTokenException e) {
            log.warn("Consumption of internal token by delegate failed for user-provided code {}: {}", userProvidedCode, e.getMessage());
            throw e;
        }
    }
}