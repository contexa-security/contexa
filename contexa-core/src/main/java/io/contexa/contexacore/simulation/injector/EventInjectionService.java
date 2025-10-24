package io.contexa.contexacore.simulation.injector;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.routing.AttackPattern;
import io.contexa.contexacore.simulation.generator.AttackScenarioGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * 이벤트 주입 서비스
 * 
 * 생성된 공격 시나리오를 실제 시스템에 주입하여 처리하도록 합니다.
 * Kafka와 Redis Streams를 통해 이벤트를 발행합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EventInjectionService {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final RedisTemplate<String, SecurityEvent> securityEventRedisTemplate;
    private final RedisTemplate<String, AttackPattern> attackPatternRedisTemplate;
    private final StringRedisTemplate stringRedisTemplate;
    private final AttackScenarioGenerator attackScenarioGenerator;
    
    @Value("${security.pipeline.kafka.topic:security-events}")
    private String kafkaTopic;
    
    @Value("${security.pipeline.redis.stream-key:security-events-stream}")
    private String redisStreamKey;
    
    // Redis 캐시 키
    private static final String ATTACK_PATTERN_KEY_PREFIX = "security:attack:pattern:";
    private static final String ATTACK_PATTERN_SET_KEY = "security:attack:patterns:all";
    private static final String SECURITY_EVENT_KEY_PREFIX = "security:event:";
    private static final String ACTIVE_INCIDENTS_KEY = "security:incidents:active";
    
    // 통계
    private long totalEventsInjected = 0;
    private long kafkaEventsPublished = 0;
    private long redisEventsPublished = 0;
    private long attackPatternsStored = 0;
    
    /**
     * 단일 보안 이벤트 주입
     */
    public CompletableFuture<Boolean> injectEvent(SecurityEvent event) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                log.info("보안 이벤트 주입 시작: EventId={}, Type={}, RiskScore={}", 
                    event.getEventId(), event.getEventType(), event.getRiskScore());
                
                // 1. Kafka로 발행
                boolean kafkaSuccess = publishToKafka(event);
                
                // 2. Redis Streams로 발행
                boolean redisSuccess = publishToRedisStream(event);
                
                // 3. AttackPattern 저장 (3-Tier 라우터용)
                storeAttackPattern(event);
                
                // 4. 이벤트 캐싱
                cacheSecurityEvent(event);
                
                // 5. 활성 인시던트 추가
                addToActiveIncidents(event);
                
                totalEventsInjected++;
                
                log.info("이벤트 주입 완료 - Kafka: {}, Redis: {}, Total: {}", 
                    kafkaSuccess, redisSuccess, totalEventsInjected);
                
                return kafkaSuccess && redisSuccess;
                
            } catch (Exception e) {
                log.error("이벤트 주입 실패: {}", event.getEventId(), e);
                return false;
            }
        });
    }
    
    /**
     * 보안 이벤트 주입 (Mono 래퍼)
     */
    public Mono<Boolean> injectSecurityEvent(SecurityEvent event) {
        return Mono.fromFuture(injectEvent(event));
    }
    
    /**
     * 여러 보안 이벤트 일괄 주입
     */
    public CompletableFuture<Integer> injectEvents(List<SecurityEvent> events) {
        log.info("보안 이벤트 일괄 주입 시작: {} 개", events.size());
        
        List<CompletableFuture<Boolean>> futures = events.stream()
            .map(this::injectEvent)
            .toList();
        
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(v -> {
                long successCount = futures.stream()
                    .map(CompletableFuture::join)
                    .filter(success -> success)
                    .count();
                
                log.info("이벤트 일괄 주입 완료: 성공 {}/{}", successCount, events.size());
                return (int) successCount;
            });
    }
    
    /**
     * 공격 타입별 이벤트 생성 및 주입
     */
    public CompletableFuture<Boolean> injectAttackByType(AttackScenarioGenerator.AttackType type) {
        SecurityEvent event = attackScenarioGenerator.generateAttack(type);
        return injectEvent(event);
    }
    
    /**
     * 무작위 공격 이벤트 생성 및 주입
     */
    public CompletableFuture<Boolean> injectRandomAttack() {
        SecurityEvent event = attackScenarioGenerator.generateRandomAttack();
        return injectEvent(event);
    }
    
    /**
     * 복합 공격 시나리오 생성 및 주입
     */
    public CompletableFuture<Integer> injectComplexAttackScenario() {
        List<SecurityEvent> scenario = attackScenarioGenerator.generateComplexAttackScenario();
        
        log.info("복합 공격 시나리오 주입 시작: {} 단계", scenario.size());
        
        // 단계별로 시간 간격을 두고 주입
        List<CompletableFuture<Boolean>> futures = new ArrayList<>();
        
        for (int i = 0; i < scenario.size(); i++) {
            final SecurityEvent event = scenario.get(i);
            final int delay = i * 2; // 각 단계마다 2초 간격
            
            CompletableFuture<Boolean> future = CompletableFuture
                .supplyAsync(() -> {
                    try {
                        TimeUnit.SECONDS.sleep(delay);
                        return true;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                })
                .thenCompose(ready -> ready ? injectEvent(event) : CompletableFuture.completedFuture(false));
            
            futures.add(future);
        }
        
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(v -> {
                long successCount = futures.stream()
                    .map(CompletableFuture::join)
                    .filter(success -> success)
                    .count();
                
                log.info("복합 공격 시나리오 주입 완료: 성공 {}/{}", successCount, scenario.size());
                return (int) successCount;
            });
    }
    
    /**
     * 연속적인 공격 시뮬레이션 (지정된 기간 동안)
     */
    public void startContinuousAttackSimulation(int durationMinutes, int eventsPerMinute) {
        log.info("연속 공격 시뮬레이션 시작: {} 분 동안, 분당 {} 이벤트", durationMinutes, eventsPerMinute);
        
        CompletableFuture.runAsync(() -> {
            LocalDateTime endTime = LocalDateTime.now().plusMinutes(durationMinutes);
            int intervalMs = 60000 / eventsPerMinute;
            
            while (LocalDateTime.now().isBefore(endTime)) {
                try {
                    // 무작위 공격 이벤트 생성 및 주입
                    injectRandomAttack();
                    
                    // 가끔 복합 시나리오도 추가
                    if (Math.random() < 0.1) { // 10% 확률
                        injectComplexAttackScenario();
                    }
                    
                    Thread.sleep(intervalMs);
                    
                } catch (InterruptedException e) {
                    log.info("연속 공격 시뮬레이션 중단");
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            log.info("연속 공격 시뮬레이션 종료: 총 {} 이벤트 주입", totalEventsInjected);
        });
    }
    
    /**
     * Kafka로 이벤트 발행
     */
    private boolean publishToKafka(SecurityEvent event) {
        try {
            // 파티션 키로 sourceIp 사용
            String key = event.getSourceIp() != null ? event.getSourceIp() : event.getEventId();
            
            kafkaTemplate.send(kafkaTopic, key, event)
                .whenComplete((result, ex) -> {
                    if (ex == null) {
                        log.debug("Kafka 발행 성공: Topic={}, Key={}, Partition={}, Offset={}", 
                            kafkaTopic, key, 
                            result.getRecordMetadata().partition(), 
                            result.getRecordMetadata().offset());
                    } else {
                        log.error("Kafka 발행 실패: {}", event.getEventId(), ex);
                    }
                });
            
            kafkaEventsPublished++;
            return true;
            
        } catch (Exception e) {
            log.error("Kafka 발행 예외: {}", event.getEventId(), e);
            return false;
        }
    }
    
    /**
     * Redis Streams로 이벤트 발행
     */
    private boolean publishToRedisStream(SecurityEvent event) {
        try {
            Map<String, String> eventData = new HashMap<>();
            eventData.put("eventId", event.getEventId());
            eventData.put("eventType", event.getEventType().toString());
            eventData.put("severity", event.getSeverity().toString());
            eventData.put("sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown");
            eventData.put("targetSystem", event.getTargetSystem());
            eventData.put("riskScore", String.valueOf(event.getRiskScore()));
            eventData.put("confidence", String.valueOf(event.getConfidenceScore()));
            eventData.put("timestamp", event.getTimestamp().toString());
            eventData.put("description", event.getDescription());
            
            // 상세 정보는 JSON으로 직렬화
            if (event.getDetails() != null) {
                eventData.put("details", event.getDetails().toString());
            }
            
            // Redis Streams에 추가
            String streamId = stringRedisTemplate.opsForStream()
                .add(redisStreamKey, eventData)
                .getValue();
            
            log.debug("Redis Stream 발행 성공: StreamKey={}, StreamId={}", redisStreamKey, streamId);
            
            redisEventsPublished++;
            return true;
            
        } catch (Exception e) {
            log.error("Redis Stream 발행 실패: {}", event.getEventId(), e);
            return false;
        }
    }
    
    /**
     * AttackPattern 저장 (3-Tier 라우터용)
     */
    private void storeAttackPattern(SecurityEvent event) {
        try {
            AttackPattern pattern = attackScenarioGenerator.generateAttackPattern(event);
            
            String patternKey = ATTACK_PATTERN_KEY_PREFIX + event.getSourceIp() + ":" + event.getEventType();
            
            // 기존 패턴이 있으면 업데이트
            AttackPattern existingPattern = attackPatternRedisTemplate.opsForValue().get(patternKey);
            if (existingPattern != null) {
                existingPattern.setLastSeenAt(LocalDateTime.now());
                existingPattern.setAttemptCount(existingPattern.getAttemptCount() + 1);
                existingPattern.setConfidenceScore(Math.max(existingPattern.getConfidenceScore(), event.getRiskScore() != null ? event.getRiskScore() : 0.0));
                pattern = existingPattern;
            }
            
            // Redis에 저장 (24시간 TTL)
            attackPatternRedisTemplate.opsForValue().set(patternKey, pattern, Duration.ofHours(24));
            
            // 패턴 집합에 추가
            stringRedisTemplate.opsForSet().add(ATTACK_PATTERN_SET_KEY, patternKey);
            
            log.debug("AttackPattern 저장: Key={}, ConfidenceScore={}", patternKey, pattern.getConfidenceScore());
            
            attackPatternsStored++;
            
        } catch (Exception e) {
            log.error("AttackPattern 저장 실패: {}", event.getEventId(), e);
        }
    }
    
    /**
     * SecurityEvent 캐싱
     */
    private void cacheSecurityEvent(SecurityEvent event) {
        try {
            String eventKey = SECURITY_EVENT_KEY_PREFIX + event.getEventId();
            
            // 1시간 TTL로 캐싱
            securityEventRedisTemplate.opsForValue().set(eventKey, event, Duration.ofHours(1));
            
            log.debug("SecurityEvent 캐싱: Key={}", eventKey);
            
        } catch (Exception e) {
            log.error("SecurityEvent 캐싱 실패: {}", event.getEventId(), e);
        }
    }
    
    /**
     * 활성 인시던트 목록에 추가
     */
    private void addToActiveIncidents(SecurityEvent event) {
        try {
            // HIGH 이상의 심각도만 활성 인시던트로 관리
            if ("HIGH".equals(event.getSeverity()) || "CRITICAL".equals(event.getSeverity())) {
                stringRedisTemplate.opsForSet().add(ACTIVE_INCIDENTS_KEY, event.getEventId());
                
                // 24시간 후 자동 제거
                stringRedisTemplate.expire(ACTIVE_INCIDENTS_KEY, Duration.ofHours(24));
                
                log.debug("활성 인시던트 추가: {}", event.getEventId());
            }
            
        } catch (Exception e) {
            log.error("활성 인시던트 추가 실패: {}", event.getEventId(), e);
        }
    }
    
    /**
     * 통계 조회
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEventsInjected", totalEventsInjected);
        stats.put("kafkaEventsPublished", kafkaEventsPublished);
        stats.put("redisEventsPublished", redisEventsPublished);
        stats.put("attackPatternsStored", attackPatternsStored);
        
        // Redis에서 추가 통계
        try {
            Long activeIncidents = stringRedisTemplate.opsForSet().size(ACTIVE_INCIDENTS_KEY);
            Long storedPatterns = stringRedisTemplate.opsForSet().size(ATTACK_PATTERN_SET_KEY);
            
            stats.put("activeIncidents", activeIncidents != null ? activeIncidents : 0);
            stats.put("storedPatterns", storedPatterns != null ? storedPatterns : 0);
        } catch (Exception e) {
            log.warn("Redis 통계 조회 실패", e);
        }
        
        return stats;
    }
    
    /**
     * 모든 활성 인시던트 조회
     */
    public Set<String> getActiveIncidents() {
        try {
            return stringRedisTemplate.opsForSet().members(ACTIVE_INCIDENTS_KEY);
        } catch (Exception e) {
            log.error("활성 인시던트 조회 실패", e);
            return new HashSet<>();
        }
    }
    
    /**
     * 특정 이벤트 조회
     */
    public SecurityEvent getEvent(String eventId) {
        try {
            String eventKey = SECURITY_EVENT_KEY_PREFIX + eventId;
            return securityEventRedisTemplate.opsForValue().get(eventKey);
        } catch (Exception e) {
            log.error("이벤트 조회 실패: {}", eventId, e);
            return null;
        }
    }
}