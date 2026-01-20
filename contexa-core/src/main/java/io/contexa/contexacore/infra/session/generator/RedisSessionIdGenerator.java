package io.contexa.contexacore.infra.session.generator;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.ThreadLocalRandom;


@Slf4j
@RequiredArgsConstructor
public class RedisSessionIdGenerator implements SessionIdGenerator {

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    private static final String COLLISION_COUNTER_KEY = "mfa:collision:counter";
    private static final String GENERATE_UNIQUE_ID_SCRIPT =
            "local counter = redis.call('INCR', KEYS[1]) " +
                    "local timestamp = ARGV[1] " +
                    "local nodeId = ARGV[2] " +
                    "local random = ARGV[3] " +
                    "return timestamp .. ':' .. nodeId .. ':' .. counter .. ':' .. random";

    @Override
    public String generate(@Nullable String baseId, HttpServletRequest request) {
        return createDistributedUniqueId(baseId, request);
    }

    @Override
    public boolean isValidFormat(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return false;
        }

        return sessionId.matches("^\\d+:[a-zA-Z0-9-_]+:\\d+:[a-zA-Z0-9_-]{22,}$") ||
                sessionId.matches("^[a-zA-Z0-9_-]{32,}$");
    }

    @Override
    public String resolveCollision(String originalId, int attempt, HttpServletRequest request) {
        String nodeId = getNodeIdentifier(request);
        long timestamp = System.currentTimeMillis();
        int randomSuffix = ThreadLocalRandom.current().nextInt(1000, 9999);

        String resolvedId = String.format("%s_%s_%d_%d_%d",
                originalId.substring(0, Math.min(8, originalId.length())),
                nodeId,
                timestamp,
                attempt,
                randomSuffix);

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(resolvedId.getBytes(StandardCharsets.UTF_8));
    }

    private String createDistributedUniqueId(@Nullable String baseId, HttpServletRequest request) {
        long timestamp = System.currentTimeMillis();
        String nodeId = getNodeIdentifier(request);
        String randomPart = generateSecureRandomString(16);

        DefaultRedisScript<String> script = new DefaultRedisScript<>(GENERATE_UNIQUE_ID_SCRIPT, String.class);
        String uniqueId = redisTemplate.execute(script,
                Collections.singletonList(COLLISION_COUNTER_KEY),
                String.valueOf(timestamp),
                nodeId,
                randomPart);

        if (uniqueId != null) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(uniqueId.getBytes(StandardCharsets.UTF_8));
        }

        return generateFallbackId(baseId);
    }

    private String getNodeIdentifier(HttpServletRequest request) {
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String processId = String.valueOf(ProcessHandle.current().pid());

        String nodeInfo = String.format("%s:%d:%s", serverName, serverPort, processId);

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(nodeInfo.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(hash).substring(0, 8);
        } catch (Exception e) {
            return String.valueOf(Math.abs(nodeInfo.hashCode())).substring(0, 6);
        }
    }

    private String generateSecureRandomString(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateFallbackId(@Nullable String baseId) {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String random = generateSecureRandomString(16);

        if (StringUtils.hasText(baseId)) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString((baseId + "_" + timestamp + "_" + random)
                            .getBytes(StandardCharsets.UTF_8));
        }

        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((timestamp + "_" + random)
                        .getBytes(StandardCharsets.UTF_8));
    }
}