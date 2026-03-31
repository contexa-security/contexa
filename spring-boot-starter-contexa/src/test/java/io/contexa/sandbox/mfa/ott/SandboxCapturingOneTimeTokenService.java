package io.contexa.sandbox.mfa.ott;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * sandbox 전용 OTT capture 서비스.
 *
 * 중요한 점:
 * 1. production의 EmailOneTimeTokenService 경로를 그대로 탄다.
 * 2. 따라서 실제 MFA filter / success handler / JDBC token 저장 흐름과 동일하다.
 * 3. 차이는 테스트에서 최신 코드만 읽을 수 있게 캡처를 붙였다는 점뿐이다.
 *
 * 이 구조를 쓰는 이유:
 * - 단순 InMemory delegate로 바꾸면 MfaAuthenticationAdapter가 기대하는
 *   EmailOneTimeTokenService 타입 정보가 사라질 수 있다.
 * - sandbox에서도 실제 OTT 생성 경로를 유지해야 브라우저와 같은 서버 동작을 검증할 수 있다.
 */
public class SandboxCapturingOneTimeTokenService extends EmailOneTimeTokenService implements SandboxOttCodeCapture {

    private final Map<String, String> latestCodesByUsername = new ConcurrentHashMap<>();

    public SandboxCapturingOneTimeTokenService(
            EmailService emailService,
            JdbcTemplate jdbcTemplate,
            TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties) {
        super(emailService, jdbcTemplate, transactionTemplate, authContextProperties);
    }

    @Override
    public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
        OneTimeToken token = super.generate(request);
        if (token != null && StringUtils.hasText(token.getUsername()) && StringUtils.hasText(token.getTokenValue())) {
            latestCodesByUsername.put(token.getUsername(), token.getTokenValue());
        }
        return token;
    }

    @Override
    public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
        return super.consume(authenticationToken);
    }

    @Override
    public Optional<String> findLatestCode(String username) {
        if (!StringUtils.hasText(username)) {
            return Optional.empty();
        }
        return Optional.ofNullable(latestCodesByUsername.get(username));
    }

    @Override
    public String awaitLatestCode(String username, Duration timeout) {
        Assert.hasText(username, "username must not be blank");
        Assert.notNull(timeout, "timeout must not be null");

        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() <= deadline) {
            String code = latestCodesByUsername.get(username);
            if (StringUtils.hasText(code)) {
                return code;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new IllegalStateException("Timed out waiting for sandbox OTT code for username=" + username);
    }

    @Override
    public void clear(String username) {
        if (StringUtils.hasText(username)) {
            latestCodesByUsername.remove(username);
        }
    }

    @Override
    public void clearAll() {
        latestCodesByUsername.clear();
    }
}
