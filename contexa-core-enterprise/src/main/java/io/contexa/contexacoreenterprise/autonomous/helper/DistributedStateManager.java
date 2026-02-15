package io.contexa.contexacoreenterprise.autonomous.helper;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.*;
import io.contexa.contexacoreenterprise.properties.StateProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class DistributedStateManager {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisDistributedLockService lockService;
    private final ObjectMapper objectMapper;

    private final StateProperties stateProperties;

    private static final String STATE_PREFIX = "security:state:";

    private final Map<String, StateSnapshot> localCache = new ConcurrentHashMap<>();

    public Mono<Boolean> saveState(String key, SecurityState state) {
        return Mono.fromCallable(() -> {
            String redisKey = STATE_PREFIX + key;
            String lockKey = redisKey + ":lock";

            return Mono.fromCallable(() -> lockService.tryLock(lockKey, stateProperties.getInstanceId(), Duration.ofSeconds(5)))
                .flatMap(acquired -> {
                    if (!acquired) {
                        log.error("[DistributedStateManager] Failed to save state - lock acquisition failed: {}", key);
                        return Mono.just(false);
                    }

                    try {
                        state.setLastModified(LocalDateTime.now());
                        state.setModifiedBy(stateProperties.getInstanceId());

                        redisTemplate.opsForValue().set(
                            redisKey,
                            state,
                            stateProperties.getTtlSeconds(),
                            TimeUnit.SECONDS
                        );

                        updateLocalCache(key, state);
                        publishStateChange(key, state);

                        return Mono.just(true);

                    } finally {
                        lockService.unlock(lockKey, stateProperties.getInstanceId());
                    }
                })
                .block(Duration.ofSeconds(30));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<SecurityState> getState(String key) {
        return Mono.fromCallable(() -> {
            StateSnapshot cached = localCache.get(key);
            if (cached != null && !cached.isExpired()) {
                return cached.getState();
            }

            String redisKey = STATE_PREFIX + key;
            Object rawState = redisTemplate.opsForValue().get(redisKey);
            SecurityState state = null;

            if (rawState != null) {
                if (rawState instanceof LinkedHashMap) {
                    state = objectMapper.convertValue(rawState, SecurityState.class);
                } else if (rawState instanceof SecurityState) {
                    state = (SecurityState) rawState;
                } else {
                    log.error("[DistributedStateManager] Unknown state type: {}", rawState.getClass());
                }

                if (state != null) {
                    updateLocalCache(key, state);
                }
            }

            return state;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    private void updateLocalCache(String key, SecurityState state) {
        localCache.put(key, new StateSnapshot(state, LocalDateTime.now().plusSeconds(60)));

        if (localCache.size() > 1000) {
            localCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
        }
    }

    private void publishStateChange(String key, SecurityState state) {
        Map<String, Object> event = new HashMap<>();
        event.put("key", key);
        event.put("nodeId", stateProperties.getInstanceId());
        event.put("timestamp", LocalDateTime.now().toString());
        event.put("action", "UPDATE");

        redisTemplate.convertAndSend(stateProperties.getChanges().getChannel(), event);
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SecurityState {
        private String id;
        private String type;
        private Map<String, Object> data;
        private LocalDateTime lastModified;
        private String modifiedBy;
        private int version;
    }

    private static class StateSnapshot {
        private final SecurityState state;
        private final LocalDateTime expiryTime;

        public StateSnapshot(SecurityState state, LocalDateTime expiryTime) {
            this.state = state;
            this.expiryTime = expiryTime;
        }

        public SecurityState getState() {
            return state;
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiryTime);
        }
    }
}
