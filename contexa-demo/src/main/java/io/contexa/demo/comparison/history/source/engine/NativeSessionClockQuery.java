package io.contexa.demo.comparison.history.source.engine;

import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.demo.comparison.history.dto.SessionClockSnapshot;
import io.contexa.demo.comparison.history.source.SessionClockQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.stereotype.Component;
import java.util.List;

@Component
@Profile("contexa")
public class NativeSessionClockQuery implements SessionClockQuery {

    private final SecurityContextDataStore store;
    private final ObjectProvider<RedisOperations<String, Object>> redis;
    private final ConfigurableListableBeanFactory beans;
    private final DocumentCodec documents;

    public NativeSessionClockQuery(SecurityContextDataStore store,
            @Qualifier("generalRedisTemplate") ObjectProvider<RedisOperations<String, Object>> redis,
            ConfigurableListableBeanFactory beans, DocumentCodec documents) {
        this.store = store;
        this.redis = redis;
        this.beans = beans;
        this.documents = documents;
    }

    @Override
    public SessionClockSnapshot capture(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return empty("NO_NATIVE_SESSION");
        }
        try {
            if (store instanceof InMemorySecurityContextDataStore) {
                return snapshot("NATIVE_MEMORY_READ", store.getSessionStartedAt(sessionId),
                        store.getSessionLastRequestTime(sessionId), store.getSessionPreviousPath(sessionId));
            }
            if (store instanceof RedisSecurityContextDataStore && defaultRedisBinding()) {
                var client = redis.getIfAvailable();
                if (client == null) {
                    return empty("UNAVAILABLE");
                }
                // MGET reads the same native keys without invoking getters that refresh their TTL.
                var values = client.opsForValue().multiGet(List.of(ZeroTrustRedisKeys.sessionStartedAt(sessionId),
                        ZeroTrustRedisKeys.sessionLastRequestTime(sessionId), ZeroTrustRedisKeys.sessionPreviousPath(sessionId)));
                if (values == null || values.size() != 3) {
                    return empty("UNAVAILABLE");
                }
                return snapshot("NATIVE_REDIS_MGET_NO_TTL_TOUCH", number(values.get(0)), number(values.get(1)),
                        values.get(2) == null ? null : values.get(2).toString());
            }
            return empty("UNSUPPORTED_STORE_BINDING");
        } catch (RuntimeException unavailable) {
            return empty("UNAVAILABLE");
        }
    }

    private boolean defaultRedisBinding() {
        if (!beans.containsBeanDefinition("redisSecurityContextDataStore")
                || !beans.containsBeanDefinition("generalRedisTemplate")) {
            return false;
        }
        var definition = beans.getBeanDefinition("redisSecurityContextDataStore");
        String factory = definition.getFactoryBeanName();
        return "redisSecurityContextDataStore".equals(definition.getFactoryMethodName())
                && factory != null && factory.endsWith("CoreAutonomousAutoConfiguration$DistributedRepositoryConfiguration")
                && beans.getBeanDefinition("generalRedisTemplate").isPrimary();
    }

    private Long number(Object value) {
        return value == null ? null : Long.valueOf(value.toString());
    }

    private SessionClockSnapshot snapshot(String source, Long start, Long last, String path) {
        return new SessionClockSnapshot("READ_COMPLETED", source, start, last,
                path == null ? null : documents.hash(path));
    }

    private SessionClockSnapshot empty(String state) {
        return new SessionClockSnapshot(state, "NATIVE_SESSION_CLOCK_READ", null, null, null);
    }
}
