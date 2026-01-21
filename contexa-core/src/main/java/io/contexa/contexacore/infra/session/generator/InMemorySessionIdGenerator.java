package io.contexa.contexacore.infra.session.generator;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
public class InMemorySessionIdGenerator implements SessionIdGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generate(@Nullable String baseId, HttpServletRequest request) {
        return generateMemoryOptimizedId(baseId, request);
    }

    @Override
    public boolean isValidFormat(String sessionId) {
        return StringUtils.hasText(sessionId) &&
                sessionId.matches("^[a-zA-Z0-9_-]{16,64}$");
    }

    @Override
    public String resolveCollision(String originalId, int attempt, HttpServletRequest request) {
        long nanoTime = System.nanoTime();
        String suffix = String.valueOf(nanoTime + attempt * 1000000);

        String resolved = originalId.substring(0, Math.min(12, originalId.length())) +
                "_" + suffix;

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(resolved.getBytes(StandardCharsets.UTF_8));
    }

    private String generateMemoryOptimizedId(@Nullable String baseId, HttpServletRequest request) {
        long timestamp = System.currentTimeMillis();
        int threadId = Thread.currentThread().hashCode();

        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        String randomPart = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String combined = timestamp + "_" + threadId + "_" + randomPart;
        if (StringUtils.hasText(baseId)) {
            combined = baseId.substring(0, Math.min(8, baseId.length())) + "_" + combined;
        }

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(combined.getBytes(StandardCharsets.UTF_8));
    }
}