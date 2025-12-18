package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * 신뢰 기반 보안 표현식 루트 (Hot Path 전용)
 *
 * Redis에 사전 계산된 LLM Action을 조회하여 실시간 인가 결정을 수행합니다.
 * AI 호출 없이 Redis 조회만으로 5ms 이내 응답을 보장합니다.
 *
 * 외부기관 설계에 따른 계층 구조:
 * AbstractAISecurityExpressionRoot (공통 기반)
 *   └── TrustSecurityExpressionRoot (이 클래스)
 *
 * 사용 예시 (Action 기반):
 * - @PreAuthorize("#trust.isAllowed()")
 * - @PreAuthorize("#trust.hasActionIn('ALLOW', 'MONITOR')")
 */
@Slf4j
public class TrustSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private final RedisTemplate<String, Double> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;  // 세션-사용자 매핑 조회용
    
    // Caffeine 로컬 캐시 (1초 TTL)
    private static final Cache<String, Double> localCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();
    

    // Redis 키 프리픽스
    private static final String THREAT_SCORE_PREFIX = "threat_score:";
    private static final String THREAT_DETAIL_PREFIX = "threat_detail:";
    private static final String THREAT_PATTERN_PREFIX = "threat_pattern:";

    private static final Duration REDIS_TIMEOUT = Duration.ofMillis(5); // 5ms 타임아웃
    
    public TrustSecurityExpressionRoot(Authentication authentication,
                                       AttributeInformationPoint attributePIP,
                                       AICoreOperations aINativeProcessor,
                                       AuthorizationContext authorizationContext,
                                       AuditLogRepository auditLogRepository,
                                       RedisTemplate<String, Double> redisTemplate,
                                       StringRedisTemplate stringRedisTemplate) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.redisTemplate = redisTemplate;
        this.stringRedisTemplate = stringRedisTemplate;
        log.debug("TrustSecurityExpressionRoot 초기화 완료 - Hot Path 모드");
    }

    /**
     * Redis에서 위협 점수 조회 (캐시 적용)
     *
     * @param userId 사용자 ID
     * @return 위협 점수
     */
    private double getThreatScore(String userId) {
        String cacheKey = THREAT_SCORE_PREFIX + userId;
        
        // 1. 로컬 캐시 확인
        Double cachedScore = localCache.getIfPresent(cacheKey);
        if (cachedScore != null) {
            log.trace("로컬 캐시 히트 - userId: {}, score: {}", userId, cachedScore);
            return cachedScore;
        }
        
        // 2. Redis 조회
        try {
            Double redisScore = redisTemplate.opsForValue().get(cacheKey);
            if (redisScore != null) {
                log.trace("Redis 조회 성공 - userId: {}, score: {}", userId, redisScore);
                localCache.put(cacheKey, redisScore);
                return redisScore;
            } else {
                // Zero Trust 원칙: 신규 사용자는 중간 위험도로 시작
                // 완전히 신뢰(0.0)하지 않고, 행동 패턴을 관찰하여 점수 조정
                log.debug("Redis에 위협 점수 없음 - userId: {}, Zero Trust 기본값 사용: 0.5", userId);
                return 0.5; // 중간 위험도
            }
        } catch (Exception e) {
            log.error("Redis 조회 실패 - userId: {}, 기본값 사용: 0.5", userId, e);
            return 0.5; // 장애시 중간 위험도
        }
    }

    // extractUserId()와 getRemoteIp()는 AbstractAISecurityExpressionRoot에서 상속받아 사용

    @Override
    protected String getCurrentActivityDescription() {
        // 현재 수행 중인 활동 설명
        if (authorizationContext != null) {
            String action = authorizationContext.action();
            if (authorizationContext.resource() != null) {
                String resourceId = authorizationContext.resource().identifier();
                return String.format("%s %s", action, resourceId);
            }
            return action;
        }
        return "unknown activity";
    }
    
    /**
     * 특정 리소스에 대한 위협 점수 확인
     * 
     * @param resourceId 리소스 ID
     * @param threshold 임계값
     * @return 위협 점수가 임계값 이하이면 true
     */
    public boolean hasResourceAccess(String resourceId, double threshold) {
        String userId = extractUserId();
        if (userId == null || resourceId == null) {
            return false;
        }
        
        // 리소스별 위협 점수 조회
        String resourceKey = THREAT_SCORE_PREFIX + userId + ":" + resourceId;
        try {
            Double resourceScore = redisTemplate.opsForValue().get(resourceKey);
            if (resourceScore == null) {
                // 리소스별 점수가 없으면 사용자 전체 점수 사용
                resourceScore = getThreatScore(userId);
            }
            
            boolean hasAccess = resourceScore <= threshold;
            log.debug("hasResourceAccess - userId: {}, resourceId: {}, score: {}, threshold: {}, access: {}",
                     userId, resourceId, resourceScore, threshold, hasAccess);
            
            return hasAccess;
        } catch (Exception e) {
            log.error("리소스 접근 평가 실패 - userId: {}, resourceId: {}", userId, resourceId, e);
            return false;
        }
    }
    
    /**
     * 임시 권한 부여 확인
     * Cold Path에서 특별히 허용한 경우
     * 
     * @param permissionType 권한 타입
     * @return 임시 권한이 있으면 true
     */
    public boolean hasTemporaryPermission(String permissionType) {
        String userId = extractUserId();
        if (userId == null) {
            return false;
        }
        
        String tempPermKey = "temp_permission:" + userId + ":" + permissionType;
        try {
            Boolean hasPermission = redisTemplate.hasKey(tempPermKey);
            log.debug("hasTemporaryPermission - userId: {}, type: {}, granted: {}", 
                     userId, permissionType, hasPermission);
            return Boolean.TRUE.equals(hasPermission);
        } catch (Exception e) {
            log.error("임시 권한 확인 실패 - userId: {}, type: {}", userId, permissionType, e);
            return false;
        }
    }
    
    @Override
    protected ContextExtractionResult extractCurrentContext() {
        // 공통 메서드 사용 (Phase 2 - 중복 코드 공통화)
        return extractContextFromAuthorizationContext();
    }

    @Override
    protected String calculateContextHash() {
        // 공통 메서드 사용 (Phase 2 - 중복 코드 공통화)
        return calculateContextHashFromAuthorizationContext();
    }

    // ========================================================================
    // LLM Action 기반 메서드 구현 (Zero Trust 보안 아키텍처)
    // ========================================================================

    /**
     * Redis에서 현재 사용자의 LLM action 조회 (Hot Path)
     *
     * HCAD 분석 결과에서 action 필드를 조회한다.
     * Redis Hash: security:hcad:analysis:{userId}
     * Field: action
     *
     * 가능한 action 값: ALLOW, BLOCK, CHALLENGE, INVESTIGATE, ESCALATE, MONITOR
     * 값이 없으면 PENDING_ANALYSIS 반환
     *
     * @return LLM action 문자열
     */
    @Override
    protected String getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            log.warn("getCurrentAction: 사용자 ID를 추출할 수 없음 - PENDING_ANALYSIS 반환");
            return "PENDING_ANALYSIS";
        }

        // 로컬 캐시 확인 (action 전용) - Hot Path 성능 최적화
        String actionCacheKey = "action:" + userId;
        String cachedAction = getActionFromLocalCache(actionCacheKey);
        if (cachedAction != null) {
            log.trace("getCurrentAction: 로컬 캐시 히트 - userId: {}, action: {}", userId, cachedAction);
            return cachedAction;
        }

        // 공통 메서드를 통한 Redis Hash 조회 (Phase 2 - 중복 코드 공통화)
        String redisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        String action = getActionFromRedisHash(userId, redisKey, stringRedisTemplate);

        // 결과를 로컬 캐시에 저장 (Hot Path 성능 최적화)
        if (!"PENDING_ANALYSIS".equals(action)) {
            putActionToLocalCache(actionCacheKey, action);
        }

        return action;
    }

    // Action 전용 로컬 캐시 (1초 TTL)
    private static final Cache<String, String> actionLocalCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(1, TimeUnit.SECONDS)
            .build();

    private String getActionFromLocalCache(String key) {
        return actionLocalCache.getIfPresent(key);
    }

    private void putActionToLocalCache(String key, String action) {
        actionLocalCache.put(key, action);
    }
}