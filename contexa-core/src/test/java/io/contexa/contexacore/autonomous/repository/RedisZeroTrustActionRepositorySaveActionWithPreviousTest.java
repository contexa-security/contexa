package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIf("io.contexa.contexacore.autonomous.repository.RedisZeroTrustActionRepositorySaveActionWithPreviousTest#isLocalRedisAvailable")
class RedisZeroTrustActionRepositorySaveActionWithPreviousTest {

    private static final String REDIS_HOST =
            System.getProperty("contexa.test.redis.host",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_HOST", "localhost"));
    private static final int REDIS_PORT = Integer.parseInt(
            System.getProperty("contexa.test.redis.port",
                    System.getenv().getOrDefault("CONTEXA_TEST_REDIS_PORT", "6379")));

    private static LettuceConnectionFactory connectionFactory;
    private static RedisTemplate<String, Object> redisTemplate;
    private static StringRedisTemplate stringRedisTemplate;
    private ZeroTrustActionRedisRepository repository;

    static boolean isLocalRedisAvailable() {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(REDIS_HOST, REDIS_PORT), 500);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @BeforeAll
    static void startRedis() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration(REDIS_HOST, REDIS_PORT);
        connectionFactory = new LettuceConnectionFactory(config);
        connectionFactory.afterPropertiesSet();
        redisTemplate = RedisTestTemplates.newProductionAlignedRedisTemplate(connectionFactory);
        stringRedisTemplate = RedisTestTemplates.newStringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @BeforeEach
    void flushRedis() {
        stringRedisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });
        repository = new ZeroTrustActionRedisRepository(redisTemplate, stringRedisTemplate);
    }

    @Test
    @DisplayName("First saveActionWithPrevious records previousAction as PENDING_ANALYSIS and action as the new value")
    void firstCall_recordsPendingAsPrevious() {
        repository.saveActionWithPrevious("user-first", ZeroTrustAction.ALLOW);

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis("user-first");
        Object previous = redisTemplate.opsForHash().get(analysisKey, "previousAction");
        Object current = redisTemplate.opsForHash().get(analysisKey, "action");

        assertThat(String.valueOf(previous)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS.name());
        assertThat(String.valueOf(current)).isEqualTo(ZeroTrustAction.ALLOW.name());
    }

    @Test
    @DisplayName("Second saveActionWithPrevious rotates the previous action atomically")
    void secondCall_rotatesPreviousAtomically() {
        repository.saveActionWithPrevious("user-rotate", ZeroTrustAction.ALLOW);
        repository.saveActionWithPrevious("user-rotate", ZeroTrustAction.CHALLENGE);

        String analysisKey = ZeroTrustRedisKeys.hcadAnalysis("user-rotate");
        Object previous = redisTemplate.opsForHash().get(analysisKey, "previousAction");
        Object current = redisTemplate.opsForHash().get(analysisKey, "action");

        assertThat(String.valueOf(previous)).isEqualTo(ZeroTrustAction.ALLOW.name());
        assertThat(String.valueOf(current)).isEqualTo(ZeroTrustAction.CHALLENGE.name());
    }
}
