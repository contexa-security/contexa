package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.event.domain.SecurityIncidentEvent;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.TieredEventProcessor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.stream.RecordId;
import org.springframework.data.redis.connection.stream.StreamRecords;
import org.springframework.data.redis.connection.stream.StringRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Redis 기반 보안 이벤트 발행자
 *
 * Redis Pub/Sub과 Redis Stream을 활용하여 실시간 이벤트 전파 및 이력 관리를 수행합니다.
 * Pub/Sub으로 즉시 전파하고, Stream으로 이벤트 이력을 보관합니다.
 *
 * eventRedisTemplate을 사용하여 타입 정보 없이 깔끔한 JSON으로 직렬화합니다.
 */
@Slf4j
public class RedisSecurityEventPublisher implements SecurityEventPublisher {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;
    private final TieredEventProcessor tieredEventProcessor;

    public RedisSecurityEventPublisher(
            @Qualifier("eventRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            ObjectMapper objectMapper,
            TieredEventProcessor tieredEventProcessor) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        this.tieredEventProcessor = tieredEventProcessor;
    }
    
    @Value("${security.redis.channel.authorization:security:authorization:events}")
    private String authorizationChannel;

    @Value("${security.redis.channel.authentication:security:events}")
    private String authenticationChannel;

    @Value("${security.redis.channel.incident:security:incidents}")
    private String incidentChannel;

    @Value("${security.redis.channel.threat:security:threats}")
    private String threatChannel;

    @Value("${security.redis.channel.audit:security:audit:events}")
    private String auditChannel;

    @Value("${security.redis.channel.general:security:events}")
    private String generalChannel;
    
    @Value("${security.redis.stream.authorization:security:stream:authorization}")
    private String authorizationStream;
    
    @Value("${security.redis.stream.incident:security:stream:incident}")
    private String incidentStream;
    
    @Value("${security.redis.stream.threat:security:stream:threat}")
    private String threatStream;
    
    @Value("${security.redis.stream.audit:security:stream:audit}")
    private String auditStream;
    
    @Value("${security.redis.stream.general:security:stream:general}")
    private String generalStream;
    
    @Value("${security.redis.stream.authentication:security:stream:authentication}")
    private String authenticationStream;
    
    @Value("${security.redis.stream.maxlen:10000}")
    private long streamMaxLength;
    
    @Value("${security.redis.ttl.minutes:60}")
    private long ttlMinutes;
    
    @Override
    public void publishAuthorizationEvent(AuthorizationDecisionEvent event) {
        try {
            // Redis Pub/Sub으로 실시간 전파
            redisTemplate.convertAndSend(authorizationChannel, event);
            
            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(authorizationStream);
            
            RecordId recordId = redisTemplate.opsForStream().add(record);
            
            // Stream 크기 제한 (최대 10000개 유지)
            redisTemplate.opsForStream().trim(authorizationStream, streamMaxLength);
            
            // 중요 이벤트는 별도 키로 저장 (TTL 적용)
            if (event.getResult() == AuthorizationDecisionEvent.AuthorizationResult.DENIED) {
                String key = ZeroTrustRedisKeys.authDenied(event.getPrincipal(), event.getEventId());
                redisTemplate.opsForValue().set(key, event, Duration.ofMinutes(ttlMinutes));
            }
            
            log.debug("Authorization event published to Redis: eventId={}, principal={}, result={}", 
                event.getEventId(), event.getPrincipal(), event.getResult());
                
        } catch (Exception e) {
            log.error("Failed to publish authorization event to Redis: eventId={}", 
                event.getEventId(), e);
        }
    }
    
    @Override
    public void publishSecurityIncident(SecurityIncidentEvent event) {
        try {
            // Redis Pub/Sub으로 실시간 전파
            redisTemplate.convertAndSend(incidentChannel, event);
            
            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(incidentStream);
            
            RecordId recordId = redisTemplate.opsForStream().add(record);
            
            // Stream 크기 제한
            redisTemplate.opsForStream().trim(incidentStream, streamMaxLength);
            
            // 중요 사고는 별도 키로 저장 (긴 TTL)
            if (event.getSeverity() == SecurityIncidentEvent.IncidentSeverity.CRITICAL ||
                event.getSeverity() == SecurityIncidentEvent.IncidentSeverity.HIGH) {
                String key = ZeroTrustRedisKeys.incidentCritical(event.getIncidentId());
                redisTemplate.opsForValue().set(key, event, Duration.ofHours(24));
            }
            
            log.info("Security incident published to Redis: incidentId={}, severity={}", 
                event.getIncidentId(), event.getSeverity());
                
        } catch (Exception e) {
            log.error("Failed to publish security incident to Redis: incidentId={}", 
                event.getIncidentId(), e);
        }
    }
    
    @Override
    public void publishThreatDetection(ThreatDetectionEvent event) {
        try {
            // Redis Pub/Sub으로 실시간 전파
            redisTemplate.convertAndSend(threatChannel, event);
            
            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(threatStream);
            
            RecordId recordId = redisTemplate.opsForStream().add(record);
            
            // Stream 크기 제한
            redisTemplate.opsForStream().trim(threatStream, streamMaxLength);
            
            // 고위험 위협은 별도 키로 저장
            if (event.getThreatLevel() == ThreatDetectionEvent.ThreatLevel.CRITICAL ||
                event.getThreatLevel() == ThreatDetectionEvent.ThreatLevel.HIGH) {
                String key = ZeroTrustRedisKeys.threatHigh(event.getThreatId());
                redisTemplate.opsForValue().set(key, event, Duration.ofHours(12));

                // 위협 카운터 증가
                String counterKey = ZeroTrustRedisKeys.threatCounter(event.getThreatType());
                redisTemplate.opsForValue().increment(counterKey);
            }
            
            log.info("Threat detection published to Redis: threatId={}, level={}, confidence={}", 
                event.getThreatId(), event.getThreatLevel(), event.getConfidenceScore());
                
        } catch (Exception e) {
            log.error("Failed to publish threat detection to Redis: threatId={}", 
                event.getThreatId(), e);
        }
    }
    
    @Override
    public void publishAuditEvent(AuditEvent event) {
        try {
            // Redis Pub/Sub으로 실시간 전파
            redisTemplate.convertAndSend(auditChannel, event);
            
            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(auditStream);
            
            redisTemplate.opsForStream().add(record);
            
            // Stream 크기 제한
            redisTemplate.opsForStream().trim(auditStream, streamMaxLength * 2); // 감사 로그는 더 많이 보관
            
            log.trace("Audit event published to Redis: eventId={}, principal={}, action={}", 
                event.getEventId(), event.getPrincipal(), event.getAction());
                
        } catch (Exception e) {
            log.error("Failed to publish audit event to Redis: eventId={}", 
                event.getEventId(), e);
        }
    }
    
    @Override
    public void publishAuthenticationSuccess(AuthenticationSuccessEvent event) {
        try {
            // 계층 결정 - Zero Trust를 위해 모든 성공 인증을 분석
            TieredEventProcessor.EventTier tier = tieredEventProcessor.determineTier(event);
            TieredEventProcessor.TierConfiguration config = tieredEventProcessor.getConfiguration(tier);
            
            String channel = determineChannel(tier, authenticationChannel);
            String stream = determineStream(tier, authenticationStream);
            
            // Redis Pub/Sub으로 실시간 전파
            redisTemplate.convertAndSend(channel, event);
            
            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            fields.put("tier", tier.name());
            fields.put("riskLevel", event.calculateRiskLevel().toString());
            
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(stream);
            
            redisTemplate.opsForStream().add(record);
            
            // Stream 크기 제한 (계층별 차등 적용)
            long maxLen = tier == TieredEventProcessor.EventTier.CRITICAL ? 
                streamMaxLength * 2 : streamMaxLength;
            redisTemplate.opsForStream().trim(stream, maxLen);
            
            // Zero Trust: 이상 징후 감지된 성공 인증은 별도 저장
            if (event.isAnomalyDetected() ||
                event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.CRITICAL) {
                String key = ZeroTrustRedisKeys.authAnomaly(event.getUserId(), event.getEventId());
                redisTemplate.opsForValue().set(key, event, Duration.ofHours(24));

                // 이상 징후 카운터 증가
                String counterKey = ZeroTrustRedisKeys.authAnomalyCounter(event.getUserId());
                redisTemplate.opsForValue().increment(counterKey);
            }

            // 사용자별 최근 인증 이력 업데이트 (Pipeline으로 최적화)
            String userKey = ZeroTrustRedisKeys.authRecent(event.getUserId());
            redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
                redisTemplate.opsForList().leftPush(userKey, event);
                redisTemplate.opsForList().trim(userKey, 0, 99); // 최근 100개만 유지
                redisTemplate.expire(userKey, Duration.ofDays(7));
                return null;
            });
            
            log.debug("Authentication success published to Redis: eventId={}, user={}, tier={}", 
                event.getEventId(), event.getUsername(), tier);
                
        } catch (Exception e) {
            log.error("Failed to publish authentication success to Redis: eventId={}", 
                event.getEventId(), e);
        }
    }
    
    @Override
    public void publishAuthenticationFailure(AuthenticationFailureEvent event) {
        try {
            // 계층 결정 - 공격 패턴 감지
            TieredEventProcessor.EventTier tier = tieredEventProcessor.determineTier(event);
            TieredEventProcessor.TierConfiguration config = tieredEventProcessor.getConfiguration(tier);
            
            String channel = determineChannel(tier, authenticationChannel);
            String stream = determineStream(tier, authenticationStream);
            
            // Redis Pub/Sub으로 실시간 전파
            redisTemplate.convertAndSend(channel, event);
            
            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            fields.put("tier", tier.name());
            fields.put("attackType", event.determineAttackType().toString());
            fields.put("failureCount", String.valueOf(event.getFailureCount()));
            
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(stream);
            
            redisTemplate.opsForStream().add(record);
            
            // Stream 크기 제한
            long maxLen = tier == TieredEventProcessor.EventTier.CRITICAL ? 
                streamMaxLength * 2 : streamMaxLength;
            redisTemplate.opsForStream().trim(stream, maxLen);
            
            // 공격 패턴 감지 시 별도 저장
            if (event.isBruteForceDetected() || event.isCredentialStuffingDetected()) {
                String key = ZeroTrustRedisKeys.authAttack(event.getSourceIp(), event.getEventId());
                redisTemplate.opsForValue().set(key, event, Duration.ofHours(48));

                // IP별 공격 카운터 증가 (TTL 수정: 1시간 → 24시간, IP 차단과 일치)
                String counterKey = ZeroTrustRedisKeys.authAttackCounter(event.getSourceIp());
                Long count = redisTemplate.opsForValue().increment(counterKey);
                redisTemplate.expire(counterKey, Duration.ofHours(24)); // 수정: 1시간 → 24시간

                // 임계치 초과 시 IP 차단 목록에 추가
                if (count != null && count > 10) {
                    String blockKey = ZeroTrustRedisKeys.authBlockedIp(event.getSourceIp());
                    redisTemplate.opsForValue().set(blockKey, true, Duration.ofHours(24));
                }
            }

            // 사용자별 실패 이력 업데이트 (Pipeline 으로 최적화)
            String userKey = ZeroTrustRedisKeys.authFailures(event.getUsername());
            redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
                redisTemplate.opsForList().leftPush(userKey, event);
                redisTemplate.opsForList().trim(userKey, 0, 49); // 최근 50개만 유지
                redisTemplate.expire(userKey, Duration.ofDays(1));
                return null;
            });
            
            log.debug("Authentication failure published to Redis: eventId={}, user={}, tier={}, attackType={}", 
                event.getEventId(), event.getUsername(), tier, event.determineAttackType());
                
        } catch (Exception e) {
            log.error("Failed to publish authentication failure to Redis: eventId={}", 
                event.getEventId(), e);
        }
    }
    
    @Override
    public void publishSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        log.info("[RedisPublisher] START publishing event - eventId={}, type={}, thread={}",
            event.getEventId(), event.getEventType(), Thread.currentThread().getName());

        try {
            // Redis Pub/Sub으로 실시간 전파
            log.info("[RedisPublisher] Publishing to Redis channel '{}' - eventId={}",
                generalChannel, event.getEventId());
            redisTemplate.convertAndSend(generalChannel, event);
            log.info("[RedisPublisher] Published to Redis channel successfully - eventId={}", event.getEventId());

            // Redis Stream에 이력 저장
            Map<String, String> fields = convertEventToFields(event);
            StringRecord record = StreamRecords.string(fields)
                .withStreamKey(generalStream);

            log.info("[RedisPublisher] Adding to Redis stream '{}' - eventId={}", generalStream, event.getEventId());
            redisTemplate.opsForStream().add(record);
            log.info("[RedisPublisher] Added to Redis stream successfully - eventId={}", event.getEventId());

            // Stream 크기 제한
            redisTemplate.opsForStream().trim(generalStream, streamMaxLength);
            
            long duration = System.currentTimeMillis() - startTime;
            log.info("[RedisPublisher] COMPLETED publishing event - eventId={}, type={}, duration={}ms",
                event.getEventId(), event.getEventType(), duration);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[RedisPublisher] FAILED to publish event - eventId={}, error: {}, duration={}ms",
                event.getEventId(), e.getMessage(), duration, e);
        }
    }
    
    /**
     * 계층별 채널 결정
     */
    private String determineChannel(TieredEventProcessor.EventTier tier, String baseChannel) {
        switch (tier) {
            case CRITICAL:
                return baseChannel + ":critical";
            case CONTEXTUAL:
                return baseChannel + ":contextual";
            case GENERAL:
                return baseChannel + ":general";
            default:
                return baseChannel;
        }
    }
    
    /**
     * 계층별 스트림 결정
     */
    private String determineStream(TieredEventProcessor.EventTier tier, String baseStream) {
        switch (tier) {
            case CRITICAL:
                return baseStream + ":critical";
            case CONTEXTUAL:
                return baseStream + ":contextual";
            case GENERAL:
                return baseStream + ":general";
            default:
                return baseStream;
        }
    }
    
    /**
     * 이벤트 객체를 Redis Stream 필드로 변환
     */
    private Map<String, String> convertEventToFields(Object event) {
        Map<String, String> fields = new HashMap<>();
        try {
            Map<String, Object> map = objectMapper.convertValue(event, Map.class);
            map.forEach((key, value) -> {
                if (value != null) {
                    fields.put(key, value.toString());
                }
            });
        } catch (Exception e) {
            log.warn("Failed to convert event to fields", e);
            fields.put("event", event.toString());
        }
        fields.put("timestamp", String.valueOf(System.currentTimeMillis()));
        return fields;
    }
}