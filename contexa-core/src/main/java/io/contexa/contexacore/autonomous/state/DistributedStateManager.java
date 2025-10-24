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

/**
 * DistributedStateManager - 분산 상태 관리자
 * 분산 환경에서 보안 평면의 상태를 일관되게 관리하고 동기화합니다.
 * 주요 기능:
 * - 분산 상태 동기화
 * - 이벤트 집계 및 상관 관계
 * - 세션 상태 관리
 * - 글로벌 메트릭 수집
 * - 장애 복구 및 리더 선출
 * 
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DistributedStateManager {
    
    // 기존 컴포넌트 재사용
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisDistributedLockService lockService;
    private final ObjectMapper objectMapper;
    
    // Redis 키 프리픽스
    private static final String STATE_PREFIX = "security:state:";
    private static final String SESSION_PREFIX = "security:session:";
    private static final String METRICS_PREFIX = "security:metrics:";
    private static final String LEADER_KEY = "security:leader";
    private static final String HEARTBEAT_PREFIX = "security:heartbeat:";
    
    // 설정값
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
    
    // 로컬 캐시
    private final Map<String, StateSnapshot> localCache = new ConcurrentHashMap<>();
    
    // 메트릭
    private final AtomicLong stateWrites = new AtomicLong(0);
    private final AtomicLong stateReads = new AtomicLong(0);
    private final AtomicLong syncOperations = new AtomicLong(0);
    
    // 리더 상태
    private volatile boolean isLeader = false;
    private volatile String currentLeader = null;
    
    // Redis 스크립트
    private RedisScript<Boolean> compareAndSetScript;
    private RedisScript<List> aggregateScript;
    
    @PostConstruct
    public void initialize() {
        log.info("분산 상태 관리자 초기화 시작 - Instance ID: {}", instanceId);
        
        // Redis 스크립트 초기화
        initializeRedisScripts();
        
        // 하트비트 시작
        startHeartbeat();
        
        // 리더 선출 참여
        participateInLeaderElection();
        
        // 상태 동기화 시작
        startStateSynchronization();
        
        log.info("분산 상태 관리자 초기화 완료");
    }
    
    /**
     * 보안 상태 저장 (메인 메서드)
     * 
     * 분산 환경에서 보안 상태를 일관되게 저장합니다.
     * 
     * @param key 상태 키
     * @param state 상태 데이터
     * @return 저장 성공 여부
     */
    public Mono<Boolean> saveState(String key, SecurityState state) {
        return Mono.fromCallable(() -> {
            stateWrites.incrementAndGet();
            
            String redisKey = STATE_PREFIX + key;
            String lockKey = redisKey + ":lock";
            
            // 분산 락 획득
            return Mono.fromCallable(() -> lockService.tryLock(lockKey, instanceId, Duration.ofSeconds(5)))
                .flatMap(acquired -> {
                    if (!acquired) {
                        log.warn("상태 저장 실패 - 락 획득 실패: {}", key);
                        return Mono.just(false);
                    }
                    
                    try {
                        // 상태 저장
                        state.setLastModified(LocalDateTime.now());
                        state.setModifiedBy(instanceId);
                        
                        redisTemplate.opsForValue().set(
                            redisKey, 
                            state, 
                            stateTtlSeconds, 
                            TimeUnit.SECONDS
                        );
                        
                        // 로컬 캐시 업데이트
                        updateLocalCache(key, state);
                        
                        // 이벤트 발행 (다른 노드에 알림)
                        publishStateChange(key, state);
                        
                        log.debug("상태 저장 성공: {}", key);
                        return Mono.just(true);
                        
                    } finally {
                        // 락 해제
                        lockService.unlock(lockKey, instanceId);
                    }
                })
                .block();
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 보안 상태 조회
     * 
     * @param key 상태 키
     * @return 보안 상태
     */
    public Mono<SecurityState> getState(String key) {
        return Mono.fromCallable(() -> {
            stateReads.incrementAndGet();
            
            // 로컬 캐시 확인
            StateSnapshot cached = localCache.get(key);
            if (cached != null && !cached.isExpired()) {
                log.debug("로컬 캐시에서 상태 조회: {}", key);
                return cached.getState();
            }
            
            // Redis에서 조회
            String redisKey = STATE_PREFIX + key;
            Object rawState = redisTemplate.opsForValue().get(redisKey);
            SecurityState state = null;
            
            if (rawState != null) {
                // LinkedHashMap인 경우 ObjectMapper로 변환
                if (rawState instanceof LinkedHashMap) {
                    state = objectMapper.convertValue(rawState, SecurityState.class);
                } else if (rawState instanceof SecurityState) {
                    state = (SecurityState) rawState;
                } else {
                    log.warn("Unknown state type: {}", rawState.getClass());
                }
                
                if (state != null) {
                    updateLocalCache(key, state);
                    log.debug("Redis에서 상태 조회: {}", key);
                }
            }
            
            return state;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 세션 상태 관리
     * 
     * 사용자 세션의 보안 상태를 추적합니다.
     * 
     * @param sessionId 세션 ID
     * @param sessionData 세션 데이터
     * @return 저장 성공 여부
     */
    public Mono<Boolean> saveSessionState(String sessionId, SessionSecurityState sessionData) {
        return Mono.fromCallable(() -> {
            String redisKey = SESSION_PREFIX + sessionId;
            
            // 세션 메타데이터 추가
            sessionData.setLastActivity(LocalDateTime.now());
            sessionData.setNodeId(instanceId);
            
            // TTL과 함께 저장
            redisTemplate.opsForValue().set(
                redisKey,
                sessionData,
                sessionData.getTimeoutSeconds(),
                TimeUnit.SECONDS
            );
            
            // 활성 세션 집합에 추가
            redisTemplate.opsForSet().add("active:sessions", sessionId);
            
            log.debug("세션 상태 저장: {}", sessionId);
            return true;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 세션 상태 조회
     */
    public Mono<SessionSecurityState> getSessionState(String sessionId) {
        return Mono.fromCallable(() -> {
            String redisKey = SESSION_PREFIX + sessionId;
            Object rawState = redisTemplate.opsForValue().get(redisKey);
            
            if (rawState == null) {
                return null;
            }
            
            // LinkedHashMap인 경우 ObjectMapper로 변환
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
    
    /**
     * 글로벌 메트릭 집계
     * 
     * 모든 노드의 메트릭을 집계합니다.
     * 
     * @param metricName 메트릭 이름
     * @param value 값
     * @param aggregationType 집계 타입
     */
    public Mono<Void> recordMetric(String metricName, double value, AggregationType aggregationType) {
        return Mono.fromRunnable(() -> {
            String redisKey = METRICS_PREFIX + metricName + ":" + getTimeWindow();
            
            switch (aggregationType) {
                case SUM:
                    redisTemplate.opsForValue().increment(redisKey, value);
                    break;
                case AVG:
                    // 평균을 위해 합계와 카운트 저장
                    redisTemplate.opsForValue().increment(redisKey + ":sum", value);
                    redisTemplate.opsForValue().increment(redisKey + ":count");
                    break;
                case MAX:
                    // 최대값 업데이트 (CAS 연산)
                    updateMaxValue(redisKey, value);
                    break;
                case MIN:
                    // 최소값 업데이트 (CAS 연산)
                    updateMinValue(redisKey, value);
                    break;
                case COUNT:
                    redisTemplate.opsForValue().increment(redisKey);
                    break;
            }
            
            // TTL 설정
            redisTemplate.expire(redisKey, aggregationWindowSeconds * 2, TimeUnit.SECONDS);
        })
        .subscribeOn(Schedulers.boundedElastic())
        .then();
    }
    
    /**
     * 집계된 메트릭 조회
     */
    public Mono<Map<String, Double>> getAggregatedMetrics(String metricName) {
        return Mono.fromCallable(() -> {
            Map<String, Double> metrics = new HashMap<>();
            
            // 현재와 이전 윈도우 조회
            String currentWindow = getTimeWindow();
            String previousWindow = getPreviousTimeWindow();
            
            for (String window : Arrays.asList(currentWindow, previousWindow)) {
                String redisKey = METRICS_PREFIX + metricName + ":" + window;
                
                // 각 집계 타입별 값 조회
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
                    
                    // 평균 계산
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
    
    /**
     * 이벤트 상관 관계 추적
     * 
     * 관련된 보안 이벤트들의 상관 관계를 추적합니다.
     * 
     * @param primaryEventId 주 이벤트 ID
     * @param relatedEventId 관련 이벤트 ID
     * @param correlationType 상관 관계 타입
     */
    public Mono<Void> correlateEvents(String primaryEventId, String relatedEventId, String correlationType) {
        return Mono.fromRunnable(() -> {
            String correlationKey = "correlation:" + primaryEventId;
            
            Map<String, Object> correlation = new HashMap<>();
            correlation.put("relatedId", relatedEventId);
            correlation.put("type", correlationType);
            correlation.put("timestamp", LocalDateTime.now().toString());
            correlation.put("nodeId", instanceId);
            
            // Redis Sorted Set으로 시간순 정렬
            redisTemplate.opsForZSet().add(
                correlationKey,
                correlation,
                System.currentTimeMillis()
            );
            
            // 역방향 연결도 저장
            String reverseKey = "correlation:reverse:" + relatedEventId;
            redisTemplate.opsForSet().add(reverseKey, primaryEventId);
            
            // TTL 설정
            redisTemplate.expire(correlationKey, stateTtlSeconds, TimeUnit.SECONDS);
            redisTemplate.expire(reverseKey, stateTtlSeconds, TimeUnit.SECONDS);
            
            log.debug("이벤트 상관 관계 저장: {} <-> {} ({})", 
                primaryEventId, relatedEventId, correlationType);
        })
        .subscribeOn(Schedulers.boundedElastic())
        .then();
    }
    
    /**
     * 관련 이벤트 조회
     */
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
    
    /**
     * 리더 선출 참여
     */
    private void participateInLeaderElection() {
        Schedulers.parallel().schedulePeriodically(() -> {
            try {
                // 리더 키에 대한 원자적 설정 시도
                Boolean acquired = redisTemplate.opsForValue().setIfAbsent(
                    LEADER_KEY,
                    instanceId,
                    leaderTtlSeconds,
                    TimeUnit.SECONDS
                );
                
                if (Boolean.TRUE.equals(acquired)) {
                    if (!isLeader) {
                        log.info("리더로 선출됨: {}", instanceId);
                        isLeader = true;
                        currentLeader = instanceId;
                        onBecomeLeader();
                    }
                    // 리더 TTL 갱신
                    redisTemplate.expire(LEADER_KEY, leaderTtlSeconds, TimeUnit.SECONDS);
                } else {
                    // 현재 리더 확인
                    String leader = (String) redisTemplate.opsForValue().get(LEADER_KEY);
                    if (!instanceId.equals(leader)) {
                        if (isLeader) {
                            log.info("리더 권한 상실: {}", instanceId);
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
    
    /**
     * 리더가 되었을 때 실행
     */
    private void onBecomeLeader() {
        // 리더 전용 작업 시작
        startLeaderTasks();
        
        // 글로벌 상태 정리
        cleanupGlobalState();
        
        // 다른 노드에 리더 변경 알림
        publishLeaderChange();
    }
    
    /**
     * 리더 권한 상실 시 실행
     */
    private void onLoseLeadership() {
        // 리더 전용 작업 중지
        stopLeaderTasks();
    }
    
    /**
     * 하트비트 시작
     */
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
            
            log.trace("하트비트 전송: {}", instanceId);
            
        }, 0, heartbeatIntervalSeconds, TimeUnit.SECONDS);
    }
    
    /**
     * 상태 동기화 시작
     */
    private void startStateSynchronization() {
        // 주기적으로 다른 노드의 상태 변경 확인
        Schedulers.parallel().schedulePeriodically(() -> {
            if (!isLeader) {
                // 팔로워는 리더의 상태를 동기화
                syncWithLeader();
            }
            
            syncOperations.incrementAndGet();
            
        }, 30, 30, TimeUnit.SECONDS);
    }
    
    /**
     * 리더와 동기화
     */
    private void syncWithLeader() {
        if (currentLeader == null || currentLeader.equals(instanceId)) {
            return;
        }
        
        log.debug("리더와 상태 동기화 시작: {}", currentLeader);
        
        // Redis pub/sub을 통해 받은 상태 변경 사항 적용
        // (실제 구현에서는 Redis pub/sub 리스너를 통해 처리)
    }
    
    /**
     * 로컬 캐시 업데이트
     */
    private void updateLocalCache(String key, SecurityState state) {
        localCache.put(key, new StateSnapshot(state, LocalDateTime.now().plusSeconds(60)));
        
        // 캐시 크기 제한
        if (localCache.size() > 1000) {
            // 오래된 엔트리 제거
            localCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
        }
    }
    
    /**
     * 상태 변경 발행
     */
    private void publishStateChange(String key, SecurityState state) {
        Map<String, Object> event = new HashMap<>();
        event.put("key", key);
        event.put("nodeId", instanceId);
        event.put("timestamp", LocalDateTime.now().toString());
        event.put("action", "UPDATE");
        
        redisTemplate.convertAndSend(stateChangesChannel, event);
    }
    
    /**
     * 리더 변경 발행
     */
    private void publishLeaderChange() {
        Map<String, Object> event = new HashMap<>();
        event.put("newLeader", instanceId);
        event.put("timestamp", LocalDateTime.now().toString());
        
        redisTemplate.convertAndSend(leaderChangesChannel, event);
    }
    
    /**
     * Redis 스크립트 초기화
     */
    private void initializeRedisScripts() {
        // Compare-and-Set 스크립트
        compareAndSetScript = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then " +
            "  redis.call('set', KEYS[1], ARGV[2]) " +
            "  return 1 " +
            "else " +
            "  return 0 " +
            "end",
            Boolean.class
        );
        
        // 집계 스크립트
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
    
    /**
     * 리더 전용 작업 시작
     */
    private void startLeaderTasks() {
        log.info("리더 전용 작업 시작");
        
        // 글로벌 메트릭 집계
        // 오래된 상태 정리
        // 장애 노드 감지
    }
    
    /**
     * 리더 전용 작업 중지
     */
    private void stopLeaderTasks() {
        log.info("리더 전용 작업 중지");
    }
    
    /**
     * 글로벌 상태 정리
     */
    private void cleanupGlobalState() {
        // 만료된 상태 제거
        // 비활성 세션 정리
        // 오래된 메트릭 삭제
    }
    
    /**
     * 최대값 업데이트 (CAS)
     */
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
    
    /**
     * 최소값 업데이트 (CAS)
     */
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
    
    /**
     * 현재 시간 윈도우
     */
    private String getTimeWindow() {
        long windowStart = (System.currentTimeMillis() / (aggregationWindowSeconds * 1000)) 
            * (aggregationWindowSeconds * 1000);
        return String.valueOf(windowStart);
    }
    
    /**
     * 이전 시간 윈도우
     */
    private String getPreviousTimeWindow() {
        long windowStart = ((System.currentTimeMillis() / (aggregationWindowSeconds * 1000)) - 1) 
            * (aggregationWindowSeconds * 1000);
        return String.valueOf(windowStart);
    }
    
    /**
     * 메트릭 조회
     */
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
    
    /**
     * 활성 노드 목록 조회
     */
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
    
    // 내부 클래스들
    
    /**
     * 보안 상태
     */
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
    
    /**
     * 세션 보안 상태
     */
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
    
    /**
     * 상태 스냅샷
     */
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
    
    /**
     * 이벤트 상관 관계
     */
    @Builder
    @Getter
    public static class EventCorrelation {
        private final String primaryEventId;
        private final String relatedEventId;
        private final String correlationType;
        private final LocalDateTime timestamp;
        private final String nodeId;
    }
    
    /**
     * 노드 정보
     */
    @Builder
    @Getter
    public static class NodeInfo {
        private final String nodeId;
        private final boolean isLeader;
        private final LocalDateTime lastHeartbeat;
        private final Map<String, Object> metrics;
    }
    
    /**
     * 집계 타입
     */
    public enum AggregationType {
        SUM,    // 합계
        AVG,    // 평균
        MAX,    // 최대값
        MIN,    // 최소값
        COUNT   // 카운트
    }
}