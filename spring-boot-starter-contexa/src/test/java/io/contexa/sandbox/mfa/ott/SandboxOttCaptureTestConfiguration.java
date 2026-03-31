package io.contexa.sandbox.mfa.ott;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * sandbox 전용 OTT capture 설정.
 *
 * 테스트에서만 OneTimeTokenService를 in-memory delegate 위에 감싼다.
 * 실제 MFA 웹 흐름은 그대로 유지하고, 생성된 코드만 sandbox에서 읽을 수 있게 만든다.
 * 이 패키지를 삭제해도 운영 코드에는 아무런 side effect가 남지 않는다.
 */
@TestConfiguration(proxyBeanMethods = false)
public class SandboxOttCaptureTestConfiguration {

    @Bean
    public SandboxCapturingOneTimeTokenService sandboxCapturingOneTimeTokenService(
            EmailService emailService,
            JdbcTemplate jdbcTemplate,
            TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties) {
        return new SandboxCapturingOneTimeTokenService(
                emailService,
                jdbcTemplate,
                transactionTemplate,
                authContextProperties);
    }

    @Bean
    @Primary
    public OneTimeTokenService sandboxOneTimeTokenService(
            SandboxCapturingOneTimeTokenService sandboxCapturingOneTimeTokenService) {
        return sandboxCapturingOneTimeTokenService;
    }

    @Bean
    public SandboxOttCodeCapture sandboxOttCodeCapture(
            SandboxCapturingOneTimeTokenService sandboxCapturingOneTimeTokenService) {
        return sandboxCapturingOneTimeTokenService;
    }
}
