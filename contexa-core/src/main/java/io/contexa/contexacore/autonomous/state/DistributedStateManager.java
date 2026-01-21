package io.contexa.contexacore.autonomous.state;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class DistributedStateManager {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisDistributedLockService lockService;
    private final ObjectMapper objectMapper;

    private static final String STATE_PREFIX = "security:state:";
    private static final String SESSION_PREFIX = "security:session:";
    private static final String METRICS_PREFIX = "security:metrics:";
    private static final String LEADER_KEY = "security:leader";
    private static final String HEARTBEAT_PREFIX = "security:heartbeat:";

    @Value("${security.state.ttl-seconds:3600}")
    private int stateTtlSeconds;
    
    @Value("${security.state.heartbeat-interval:10}")
    private int heartbeatIntervalSeconds;
    
    @Value("${security.state.leader-ttl:30}")
    private int leaderTtlSeconds;
    
    @Value("${security.state.aggregation-window:60}")
    private int aggregationWindowSeconds;
    
    @Value("${security.state.instance-id:#{T(java.util.UUID).randomUUID().toString()}}")
    private String instanceId;
    
    @Value("${security.state.changes.channel:state:changes}")
    private String stateChangesChannel;
    
    @Value("${security.state.leader.channel:leader:changes}")
    private String leaderChangesChannel;

    private final Map<String, StateSnapshot> localCache = new ConcurrentHashMap<>();

    private final AtomicLong stateWrites = new AtomicLong(0);
    private final AtomicLong stateReads = new AtomicLong(0);
    private final AtomicLong syncOperations = new AtomicLong(0);

    private volatile boolean isLeader = false;
    private volatile String currentLeader = null;

    private RedisScript<Boolean> compareAndSetScript;
    private RedisScript<List> aggregateScript;
    
    @PostConstruct
    public void initialize() {

        initializeRedisScripts();

        startHeartbeat();

        participateInLeaderElection();

        startStateSynchronization();
        
            }

    public Mono<Boolean> saveState(String key, SecurityState state) {
        return Mono.fromCallable(() -> {
            stateWrites.incrementAndGet();
            
            String redisKey = STATE_PREFIX + key;
            String lockKey = redisKey + ":lock";

            return Mono.fromCallable(() -> lockService.tryLock(lockKey, instanceId, Duration.ofSeconds(5)))
                .flatMap(acquired -> {
                    if (!acquired) {
                        log.warn("상태 저장 실패 - 락 획득 실패: {}", key);
                        return Mono.just(false);
                    }
                    
                    try {
                        
                        state.setLastModified(LocalDateTime.now());
                        state.setModifiedBy(instanceId);
                        
                        redisTemplate.opsForValue().set(
                            redisKey, 
                            state, 
                            stateTtlSeconds, 
                            TimeUnit.SECONDS
                        );

                        updateLocalCache(key, state);

                        publishStateChange(key, state);
                        
                                                return Mono.just(true);
                        
                    } finally {
                        
                        lockService.unlock(lockKey, instanceId);
                    }
                })
                .block();
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<SecurityState> getState(String key) {
        return Mono.fromCallable(() -> {
            stateReads.incrementAndGet();

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
                    log.warn("Unknown state type: {}", rawState.getClass());
                }
                
                if (state != null) {
                    updateLocalCache(key, state);
                                    }
            }
            
            return state;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Boolean> saveSessionState(String sessionId, SessionSecurityState sessionData) {
        return Mono.fromCallable(() -> {
            String redisKey = SESSION_PREFIX + sessionId;

            sessionData.setLastActivity(LocalDateTime.now());
            sessionData.setNodeId(instanceId);

            redisTemplate.opsForValue().set(
                redisKey,
                sessionData,
                sessionData.getTimeoutSeconds(),
                TimeUnit.SECONDS
            );

            redisTemplate.opsForSet().add("active:sessions", sessionId);
            
                        return true;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<SessionSecurityState> getSessionState(String sessionId) {
        return Mono.fromCallable(() -> {
            String redisKey = SESSION_PREFIX + sessionId;
            Object rawState = redisTemplate.opsForValue().get(redisKey);
            
            if (rawState == null) {
                return null;
            }

            if (rawState instanceof LinkedHashMap) {
                return objectMapper.convertValue(rawState, SessionSecurityState.class);
            } else if (rawState instanceof SessionSecurityState) {
                return (SessionSecurityState) rawState;
            } else {
                log.warn("Unknown session state type: {}", rawState.getClass());
                return null;
            }
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Void> recordMetric(String metricName, double value, AggregationType aggregationType) {
        return Mono.fromRunnable(() -> {
            String redisKey = METRICS_PREFIX + metricName + ":" + getTimeWindow();
            
            switch (aggregationType) {
                case SUM:
                    redisTemplate.opsForValue().increment(redisKey, value);
                    break;
                case AVG:
                    
                    redisTemplate.opsForValue().increment(redisKey + ":sum", value);
                    redisTemplate.opsForValue().increment(redisKey + ":count");
                    break;
                case MAX:
                    
                    updateMaxValue(redisKey, value);
                    break;
                case MIN:
                    
                    updateMinValue(redisKey, value);
                    break;
                case COUNT:
                    redisTemplate.opsForValue().increment(redisKey);
                    break;
            }

            redisTemplate.expire(redisKey, aggregationWindowSeconds * 2, TimeUnit.SECONDS);
        })
        .subscribeOn(Schedulers.boundedElastic())
        .then();
    }

    public Mono<Map<String, Double>> getAggregatedMetrics(String metricName) {
        return Mono.fromCallable(() -> {
            Map<String, Double> metrics = new HashMap<>();

            String currentWindow = getTimeWindow();
            String previousWindow = getPreviousTimeWindow();
            
            for (String window : Arrays.asList(currentWindow, previousWindow)) {
                String redisKey = METRICS_PREFIX + metricName + ":" + window;

                Object sum = redisTemplate.opsForValue().get(redisKey);
                Object count = redisTemplate.opsForValue().get(redisKey + ":count");
                Object max = redisTemplate.opsForValue().get(redisKey + ":max");
                Object min = redisTemplate.opsForValue().get(redisKey + ":min");
                
                if (sum != null) {
                    metrics.put(window + ":sum", ((Number) sum).doubleValue());
                }
                if (count != null) {
                    long countValue = ((Number) count).longValue();
                    metrics.put(window + ":count", (double) countValue);

                    if (sum != null && countValue > 0) {
                        double avgSum = ((Number) redisTemplate.opsForValue()
                            .get(redisKey + ":sum")).doubleValue();
                        metrics.put(window + ":avg", avgSum / countValue);
                    }
                }
                if (max != null) {
                    metrics.put(window + ":max", ((Number) max).doubleValue());
                }
                if (min != null) {
                    metrics.put(window + ":min", ((Number) min).doubleValue());
                }
            }
            
            return metrics;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Void> correlateEvents(String primaryEventId, String relatedEventId, String correlationType) {
        return Mono.fromRunnable(() -> {
            String correlationKey = "correlation:" + primaryEventId;
            
            Map<String, Object> correlation = new HashMap<>();
            correlation.put("relatedId", relatedEventId);
            correlation.put("type", correlationType);
            correlation.put("timestamp", LocalDateTime.now().toString());
            correlation.put("nodeId", instanceId);

            redisTemplate.opsForZSet().add(
                correlationKey,
                correlation,
                System.currentTimeMillis()
            );

            String reverseKey = "correlation:reverse:" + relatedEventId;
            redisTemplate.opsForSet().add(reverseKey, primaryEventId);

            redisTemplate.expire(correlationKey, stateTtlSeconds, TimeUnit.SECONDS);
            redisTemplate.expire(reverseKey, stateTtlSeconds, TimeUnit.SECONDS);
            
                    })
        .subscribeOn(Schedulers.boundedElastic())
        .then();
    }

    public Flux<EventCorrelation> getCorrelatedEvents(String eventId) {
        return Flux.defer(() -> {
            String correlationKey = "correlation:" + eventId;
            
            Set<Object> correlations = redisTemplate.opsForZSet()
                .reverseRange(correlationKey, 0, -1);
            
            if (correlations == null || correlations.isEmpty()) {
                return Flux.empty();
            }
            
            return Flux.fromIterable(correlations)
                .map(obj -> {
                    Map<String, Object> data;
                    if (obj instanceof LinkedHashMap || obj instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> temp = (Map<String, Object>) obj;
                        data = temp;
                    } else {
                        log.warn("Unknown correlation type: {}", obj.getClass());
                        return null;
                    }
                    
                    return EventCorrelation.builder()
                        .primaryEventId(eventId)
                        .relatedEventId((String) data.get("relatedId"))
                        .correlationType((String) data.get("type"))
                        .timestamp(LocalDateTime.parse((String) data.get("timestamp")))
                        .nodeId((String) data.get("nodeId"))
                        .build();
                })
                .filter(Objects::nonNull)
                .subscribeOn(Schedulers.boundedElastic());
        });
    }

    private void participateInLeaderElection() {
        Schedulers.parallel().schedulePeriodically(() -> {
            try {
                
                Boolean acquired = redisTemplate.opsForValue().setIfAbsent(
                    LEADER_KEY,
                    instanceId,
                    leaderTtlSeconds,
                    TimeUnit.SECONDS
                );
                
                if (Boolean.TRUE.equals(acquired)) {
                    if (!isLeader) {
                                                isLeader = true;
                        currentLeader = instanceId;
                        onBecomeLeader();
                    }
                    
                    redisTemplate.expire(LEADER_KEY, leaderTtlSeconds, TimeUnit.SECONDS);
                } else {
                    
                    String leader = (String) redisTemplate.opsForValue().get(LEADER_KEY);
                    if (!instanceId.equals(leader)) {
                        if (isLeader) {
                                                        isLeader = false;
                            onLoseLeadership();
                        }
                        currentLeader = leader;
                    }
                }
            } catch (Exception e) {
                log.error("리더 선출 참여 실패", e);
            }
        }, 0, heartbeatIntervalSeconds, TimeUnit.SECONDS);
    }

    private void onBecomeLeader() {
        
        startLeaderTasks();

        cleanupGlobalState();

        publishLeaderChange();
    }

    private void onLoseLeadership() {
        
        stopLeaderTasks();
    }

    private void startHeartbeat() {
        Schedulers.parallel().schedulePeriodically(() -> {
            String heartbeatKey = HEARTBEAT_PREFIX + instanceId;
            
            Map<String, Object> heartbeat = new HashMap<>();
            heartbeat.put("timestamp", LocalDateTime.now().toString());
            heartbeat.put("isLeader", isLeader);
            heartbeat.put("stateWrites", stateWrites.get());
            heartbeat.put("stateReads", stateReads.get());
            heartbeat.put("syncOperations", syncOperations.get());
            
            redisTemplate.opsForValue().set(
                heartbeatKey,
                heartbeat,
                heartbeatIntervalSeconds * 3,
                TimeUnit.SECONDS
            );

        }, 0, heartbeatIntervalSeconds, TimeUnit.SECONDS);
    }

    private void startStateSynchronization() {
        
        Schedulers.parallel().schedulePeriodically(() -> {
            if (!isLeader) {
                
                syncWithLeader();
            }
            
            syncOperations.incrementAndGet();
            
        }, 30, 30, TimeUnit.SECONDS);
    }

    private void syncWithLeader() {
        if (currentLeader == null || currentLeader.equals(instanceId)) {
            return;
        }

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
        event.put("nodeId", instanceId);
        event.put("timestamp", LocalDateTime.now().toString());
        event.put("action", "UPDATE");
        
        redisTemplate.convertAndSend(stateChangesChannel, event);
    }

    private void publishLeaderChange() {
        Map<String, Object> event = new HashMap<>();
        event.put("newLeader", instanceId);
        event.put("timestamp", LocalDateTime.now().toString());
        
        redisTemplate.convertAndSend(leaderChangesChannel, event);
    }

    private void initializeRedisScripts() {
        
        compareAndSetScript = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then " +
            "  redis.call('set', KEYS[1], ARGV[2]) " +
            "  return 1 " +
            "else " +
            "  return 0 " +
            "end",
            Boolean.class
        );

        aggregateScript = new DefaultRedisScript<>(
            "local sum = 0 " +
            "local count = 0 " +
            "for i, key in ipairs(KEYS) do " +
            "  local val = redis.call('get', key) " +
            "  if val then " +
            "    sum = sum + tonumber(val) " +
            "    count = count + 1 " +
            "  end " +
            "end " +
            "return {sum, count}",
            List.class
        );
    }

    private void startLeaderTasks() {

    }

    private void stopLeaderTasks() {
            }

    private void cleanupGlobalState() {

    }

    private void updateMaxValue(String key, double value) {
        redisTemplate.execute((RedisCallback<Object>) connection -> {
            byte[] keyBytes = key.getBytes();
            byte[] currentBytes = connection.get(keyBytes);
            
            if (currentBytes == null || Double.parseDouble(new String(currentBytes)) < value) {
                connection.set(keyBytes, String.valueOf(value).getBytes());
            }
            
            return null;
        });
    }

    private void updateMinValue(String key, double value) {
        redisTemplate.execute((RedisCallback<Object>) connection -> {
            byte[] keyBytes = key.getBytes();
            byte[] currentBytes = connection.get(keyBytes);
            
            if (currentBytes == null || Double.parseDouble(new String(currentBytes)) > value) {
                connection.set(keyBytes, String.valueOf(value).getBytes());
            }
            
            return null;
        });
    }

    private String getTimeWindow() {
        long windowStart = (System.currentTimeMillis() / (aggregationWindowSeconds * 1000)) 
            * (aggregationWindowSeconds * 1000);
        return String.valueOf(windowStart);
    }

    private String getPreviousTimeWindow() {
        long windowStart = ((System.currentTimeMillis() / (aggregationWindowSeconds * 1000)) - 1) 
            * (aggregationWindowSeconds * 1000);
        return String.valueOf(windowStart);
    }

    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        metrics.put("instanceId", instanceId);
        metrics.put("isLeader", isLeader);
        metrics.put("currentLeader", currentLeader);
        metrics.put("stateWrites", stateWrites.get());
        metrics.put("stateReads", stateReads.get());
        metrics.put("syncOperations", syncOperations.get());
        metrics.put("localCacheSize", localCache.size());
        
        return metrics;
    }

    public Flux<NodeInfo> getActiveNodes() {
        return Flux.defer(() -> {
            Set<String> keys = redisTemplate.keys(HEARTBEAT_PREFIX + "*");
            
            if (keys == null || keys.isEmpty()) {
                return Flux.empty();
            }
            
            return Flux.fromIterable(keys)
                .map(key -> {
                    Object rawHeartbeat = redisTemplate.opsForValue().get(key);
                    
                    if (rawHeartbeat == null) {
                        return null;
                    }
                    
                    Map<String, Object> heartbeat;
                    if (rawHeartbeat instanceof LinkedHashMap || rawHeartbeat instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> temp = (Map<String, Object>) rawHeartbeat;
                        heartbeat = temp;
                    } else {
                        log.warn("Unknown heartbeat type: {}", rawHeartbeat.getClass());
                        return null;
                    }
                    
                    String nodeId = key.replace(HEARTBEAT_PREFIX, "");
                    
                    return NodeInfo.builder()
                        .nodeId(nodeId)
                        .isLeader((Boolean) heartbeat.get("isLeader"))
                        .lastHeartbeat(LocalDateTime.parse((String) heartbeat.get("timestamp")))
                        .metrics(heartbeat)
                        .build();
                })
                .filter(Objects::nonNull)
                .subscribeOn(Schedulers.boundedElastic());
        });
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

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionSecurityState {
        private String sessionId;
        private String userId;
        private double riskScore;
        private Map<String, Object> attributes;
        private LocalDateTime lastActivity;
        private String nodeId;
        private int timeoutSeconds;
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

    @Builder
    @Getter
    public static class EventCorrelation {
        private final String primaryEventId;
        private final String relatedEventId;
        private final String correlationType;
        private final LocalDateTime timestamp;
        private final String nodeId;
    }

    @Builder
    @Getter
    public static class NodeInfo {
        private final String nodeId;
        private final boolean isLeader;
        private final LocalDateTime lastHeartbeat;
        private final Map<String, Object> metrics;
    }

    public enum AggregationType {
        SUM,    
        AVG,    
        MAX,    
        MIN,    
        COUNT   
    }
}