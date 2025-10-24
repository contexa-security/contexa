package io.contexa.contexacore.infra.session.generator;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * HTTP Session 환경에 최적화된 세션 ID 생성기
 */
@Slf4j
public class HttpSessionIdGenerator implements SessionIdGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generate(@Nullable String baseId, HttpServletRequest request) {
        if (StringUtils.hasText(baseId)) {
            String enhanced = enhanceSessionId(baseId, request);
            if (isValidFormat(enhanced)) {
                return enhanced;
            }
        }
        return generateHttpSessionOptimizedId(request);
    }

    @Override
    public boolean isValidFormat(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }
        return sessionId.matches("^[a-zA-Z0-9_-]{32,}$") && sessionId.length() <= 128;
    }

    @Override
    public String resolveCollision(String originalId, int attempt, HttpServletRequest request) {
        String suffix = String.valueOf(System.nanoTime() + attempt * 1000);
        String sessionId = request.getSession().getId();

        String resolved = originalId.substring(0, Math.min(16, originalId.length())) +
                "_" + sessionId.hashCode() + "_" + suffix;

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(resolved.getBytes(StandardCharsets.UTF_8));
    }

    private String generateHttpSessionOptimizedId(HttpServletRequest request) {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String serverInfo = request.getServerName() + ":" + request.getServerPort();

        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String combined = timestamp + "_" + serverInfo.hashCode() + "_" + randomPart;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(combined.getBytes(StandardCharsets.UTF_8));
        }
    }

    private String enhanceSessionId(String baseId, HttpServletRequest request) {
        String sessionInfo = request.getSession().getId();
        String clientInfo = request.getRemoteAddr();

        String enhanced = baseId + "_" + sessionInfo.hashCode() + "_" + clientInfo.hashCode();
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(enhanced.getBytes(StandardCharsets.UTF_8));
    }
}