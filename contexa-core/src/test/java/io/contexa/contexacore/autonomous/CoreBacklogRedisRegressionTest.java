package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockableServletOutputStream;
import io.contexa.contexacore.autonomous.blocking.BlockingDecisionRegistry;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.awaitility.Awaitility;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.RedisZeroTrustSecurityService;
import org.springframework.test.util.ReflectionTestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.redisson.Redisson;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@EnabledIfEnvironmentVariable(named = "CONTEXA_BACKLOG_REDIS_PORT", matches = "[0-9]+")
class CoreBacklogRedisRegressionTest {
    private static LettuceConnectionFactory factory;
    private static RedisTemplate<String, Object> objects;
    private static StringRedisTemplate strings;
    private static ZeroTrustActionRedisRepository actions;
    private static RedissonClient firstClient;
    private static RedissonClient secondClient;
    private static BlockingDecisionRegistry firstSignals;
    private static BlockingDecisionRegistry secondSignals;

    @BeforeAll
    static void connectToIsolatedRedis() {
        int port = Integer.parseInt(System.getenv("CONTEXA_BACKLOG_REDIS_PORT"));
        factory = new LettuceConnectionFactory("127.0.0.1", port);
        factory.afterPropertiesSet();
        objects = RedisTestTemplates.newProductionAlignedRedisTemplate(factory);
        strings = RedisTestTemplates.newStringRedisTemplate(factory);
        actions = new ZeroTrustActionRedisRepository(objects, strings);
        Config config = new Config();
        config.useSingleServer().setAddress("redis://127.0.0.1:" + port)
                .setConnectionMinimumIdleSize(1).setConnectionPoolSize(2)
                .setSubscriptionConnectionMinimumIdleSize(1).setSubscriptionConnectionPoolSize(2);
        firstClient = Redisson.create(config);
        secondClient = Redisson.create(config);
        firstSignals = new BlockingDecisionRegistry(firstClient);
        secondSignals = new BlockingDecisionRegistry(secondClient);
    }

    @AfterAll
    static void close() {
        if (firstClient != null) firstClient.shutdown();
        if (secondClient != null) secondClient.shutdown();
        if (factory != null) factory.destroy();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ACTION", "FLAG", "ALLOW_WITH_BLOCK_FLAG"})
    void logoutRetainsBlockAndMfaRegardlessOfPartialState(String state) {
        String user = UUID.randomUUID().toString();
        if ("ACTION".equals(state)) actions.saveAction(user, ZeroTrustAction.BLOCK, Map.of());
        if ("ALLOW_WITH_BLOCK_FLAG".equals(state)) actions.saveAction(user, ZeroTrustAction.ALLOW, Map.of());
        if (!"ACTION".equals(state)) actions.setBlockedFlag(user);
        actions.setBlockMfaPending(user);
        actions.incrementBlockMfaFailCount(user);
        actions.incrementBlockMfaFailCount(user);
        Long before = strings.getExpire(ZeroTrustRedisKeys.blockMfaFailCount(user), TimeUnit.MILLISECONDS);

        actions.removeLogoutData(user);

        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actions.isBlockMfaPending(user)).isTrue();
        assertThat(actions.getBlockMfaFailCount(user)).isEqualTo(2);
        Long after = strings.getExpire(ZeroTrustRedisKeys.blockMfaFailCount(user), TimeUnit.MILLISECONDS);
        assertThat(after).isPositive().isLessThanOrEqualTo(before);
        actions.removeAllUserData(user);
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void approvedReleaseAndNonBlockedLogoutKeepTheirExistingMeanings() {
        String user = UUID.randomUUID().toString();
        actions.saveAction(user, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(user);
        actions.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.ALLOW);
        actions.removeLogoutData(user);
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void requiredSignalReachesAnotherRegistryAndStopsItsOpenResponse() throws Exception {
        String user = UUID.randomUUID().toString();
        MockHttpServletResponse response = new MockHttpServletResponse();
        BlockableServletOutputStream stream = new BlockableServletOutputStream(
                response.getOutputStream(), secondSignals, user, response);
        stream.write('a');
        firstSignals.registerBlockAndAwait(user);
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> secondSignals.isBlocked(user));
        assertThatThrownBy(() -> stream.write('b')).isInstanceOf(IOException.class);
        assertThat(response.getContentAsString()).contains("__CONTEXA_RESPONSE_BLOCKED__:BLOCK");
        firstSignals.registerBlockAndAwait(user);
        assertThat(secondSignals.isBlocked(user)).isTrue();
        firstSignals.registerUnblock(user);
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> !secondSignals.isBlocked(user));
    }


    @Test
    void distributedLogoutRemovesOnlyItsSessionAndPreservesRemoteBlock() {
        String user = UUID.randomUUID().toString();
        String a = UUID.randomUUID().toString();
        String b = UUID.randomUUID().toString();
        RedisZeroTrustSecurityService service = new RedisZeroTrustSecurityService(
                objects, null, new SecurityZeroTrustProperties(), actions);
        service.setBlockingSignalBroadcaster(firstSignals);
        ReflectionTestUtils.invokeMethod(service, "doRegisterSession", user, a);
        ReflectionTestUtils.invokeMethod(service, "doRegisterSession", user, b);
        actions.saveAction(user, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(user);
        actions.setBlockMfaPending(user);
        actions.incrementBlockMfaFailCount(user);
        firstSignals.registerBlockAndAwait(user);
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> secondSignals.isBlocked(user));

        service.cleanupOnLogout(user, b);

        assertThat(objects.opsForSet().members(ZeroTrustRedisKeys.userSessions(user))).containsExactly(a);
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(actions.getBlockMfaFailCount(user)).isEqualTo(1);
        assertThat(secondSignals.isBlocked(user)).isTrue();
        service.invalidateAllUserSessions(user, "Controlled forced logout");
        service.cleanupOnLogout(user, null);
        assertThat(service.isSessionInvalidated(a)).isTrue();
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(secondSignals.isBlocked(user)).isTrue();
        actions.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);
        firstSignals.registerUnblock(user);
        Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> !secondSignals.isBlocked(user));
        actions.removeAllUserData(user);
    }

    @Test
    void requiredFlagAndSignalStorageFailuresPropagate() {
        StringRedisTemplate broken = mock(StringRedisTemplate.class);
        when(broken.opsForValue()).thenThrow(new RedisConnectionFailureException("Controlled Redis failure"));
        ZeroTrustActionRedisRepository repository = new ZeroTrustActionRedisRepository(objects, broken);
        assertThatThrownBy(() -> repository.setBlockedFlag(UUID.randomUUID().toString()))
                .isInstanceOf(IllegalStateException.class);

        RedissonClient client = mock(RedissonClient.class);
        RTopic topic = mock(RTopic.class);
        when(client.getTopic(anyString())).thenReturn(topic);
        when(topic.publish(anyString())).thenThrow(new IllegalStateException("Controlled publish failure"));
        BlockingDecisionRegistry registry = new BlockingDecisionRegistry(client);
        String user = UUID.randomUUID().toString();
        assertThatThrownBy(() -> registry.registerBlockAndAwait(user)).isInstanceOf(IllegalStateException.class);
        assertThat(registry.isBlocked(user)).isTrue();
    }

    @Test
    void defaultAllowTtlExpiresWhileBlockFlagRemainsInBothRepositories() {
        String user = UUID.randomUUID().toString();
        String blocked = UUID.randomUUID().toString();
        InMemoryZeroTrustActionRepository memory = new InMemoryZeroTrustActionRepository();
        actions.saveAction(user, ZeroTrustAction.ALLOW, Map.of());
        memory.saveAction(user, ZeroTrustAction.ALLOW, Map.of());
        actions.saveAction(blocked, ZeroTrustAction.ALLOW, Map.of());
        memory.saveAction(blocked, ZeroTrustAction.ALLOW, Map.of());
        actions.setBlockedFlag(blocked);
        memory.setBlockedFlag(blocked);
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(memory.getCurrentAction(user)).isEqualTo(ZeroTrustAction.ALLOW);
        Awaitility.await().atMost(Duration.ofSeconds(20)).untilAsserted(() -> {
            assertThat(actions.getCurrentAction(user, "ttl-context")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
            assertThat(memory.getCurrentAction(user, "ttl-context")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        });
        assertThat(actions.getCurrentAction(blocked)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(memory.getCurrentAction(blocked)).isEqualTo(ZeroTrustAction.BLOCK);
        actions.removeAllUserData(user);
        actions.removeAllUserData(blocked);
    }
}

