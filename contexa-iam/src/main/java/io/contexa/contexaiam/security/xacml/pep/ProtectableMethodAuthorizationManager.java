package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacommon.annotation.AnalysisRequirement;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.exception.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.interceptor.ZeroTrustResponseInterceptor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Spring Security 표준 방식 AOP - Zero Trust 통합
 *
 * 역할:
 * - SpEL 표현식 평가
 * - @Protectable 어노테이션 속성 처리 (analysisRequirement, analysisTimeout, defaultAction, enableRuntimeInterception)
 * - LLM 분석 대기 및 action 기반 접근 제어
 * - 실시간 응답 차단 활성화 (enableRuntimeInterception)
 *
 * Phase 8: @Protectable 어노테이션 속성을 실제로 읽고 처리하도록 구현
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class ProtectableMethodAuthorizationManager {

    private final MethodSecurityExpressionHandler expressionHandler;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager dynamicAuthorizationManager;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ZeroTrustResponseInterceptor zeroTrustResponseInterceptor;

    /**
     * 분석 대기 폴링 간격 (밀리초)
     */
    private static final long POLLING_INTERVAL_MS = 100;

    /**
     * 허용된 action 목록 (ALLOW, MONITOR는 접근 허용)
     */
    private static final Set<String> ALLOWED_ACTIONS = Set.of("ALLOW", "MONITOR");

    /**
     * 사전 인가 처리
     *
     * 처리 순서:
     * 1. @Protectable 어노테이션 읽기
     * 2. analysisRequirement에 따른 분석 대기 처리
     * 3. enableRuntimeInterception 활성화
     * 4. DB에서 SpEL 표현식 조회 및 평가
     *
     * @param authentication 인증 정보 공급자
     * @param mi 메서드 호출 정보
     */
    public void preAuthorize(Supplier<Authentication> authentication, MethodInvocation mi) {
        // 1. @Protectable 어노테이션 읽기
        Protectable protectable = findProtectableAnnotation(mi);

        // 2. @Protectable이 있으면 속성 처리
        if (protectable != null) {
            String userId = extractUserId(authentication.get());
            String resourceId = getResourceId(mi);

            // 2-1. analysisRequirement에 따른 분석 대기 처리
            handleAnalysisRequirement(protectable, userId, resourceId);

            // 2-2. enableRuntimeInterception 활성화
            if (protectable.enableRuntimeInterception()) {
                enableRuntimeInterception();
            }
        }

        // 3. DB에서 SpEL 표현식 조회 및 평가 (기존 로직)
        String finalExpression = getDynamicExpression(mi, "PRE_AUTHORIZE");
        if (!StringUtils.hasText(finalExpression)) {
            return;
        }
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        if (!evaluate(finalExpression, ctx)) {
            throw new AccessDeniedException("Access is denied");
        }
    }

    public void postAuthorize(Supplier<Authentication> authentication, MethodInvocation mi, Object returnObject) {
        String finalExpression = getDynamicExpression(mi, "POST_AUTHORIZE");
        if (!StringUtils.hasText(finalExpression)) {
            return;
        }
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        expressionHandler.setReturnObject(returnObject, ctx);
        if (!evaluate(finalExpression, ctx)) {
            throw new AccessDeniedException("Access is denied");
        }
    }

    private boolean evaluate(String expressionString, EvaluationContext context) {
        try {
            Expression expression = expressionHandler.getExpressionParser().parseExpression(expressionString);
            return ExpressionUtils.evaluateAsBoolean(expression, context);
        } catch (Exception e) {
            log.error("Error evaluating SpEL expression: {}", expressionString, e);
            return false;
        }
    }

    private String getDynamicExpression(MethodInvocation mi, String phase) {
        Method method = mi.getMethod();
        String paramTypes = Arrays.stream(method.getParameterTypes()).map(Class::getSimpleName).collect(Collectors.joining(","));
        String methodIdentifier = method.getDeclaringClass().getName() + "." + method.getName() + "(" + paramTypes + ")";

        List<Policy> policies = policyRetrievalPoint.findMethodPolicies(methodIdentifier, phase);
        if (CollectionUtils.isEmpty(policies)) {
            return null;
        }
        return dynamicAuthorizationManager.getExpressionFromPolicies(policies);
    }

    // ============================================
    // @Protectable 어노테이션 처리 메서드
    // ============================================

    /**
     * @Protectable 어노테이션 찾기
     *
     * 메서드 레벨 -> 클래스 레벨 순서로 검색
     *
     * @param mi 메서드 호출 정보
     * @return @Protectable 어노테이션 (없으면 null)
     */
    private Protectable findProtectableAnnotation(MethodInvocation mi) {
        Method method = mi.getMethod();

        // 1. 메서드 레벨 확인
        Protectable protectable = method.getAnnotation(Protectable.class);
        if (protectable != null) {
            return protectable;
        }

        // 2. 클래스 레벨 확인
        return method.getDeclaringClass().getAnnotation(Protectable.class);
    }

    /**
     * analysisRequirement에 따른 분석 대기 처리
     *
     * - NOT_REQUIRED: 분석 불필요, 바로 통과
     * - PREFERRED: 분석 있으면 사용, 없으면 defaultAction 사용
     * - REQUIRED: 분석 완료까지 대기 (동기)
     * - STRICT: 분석 완료 + ALLOW action 필수
     *
     * @param protectable @Protectable 어노테이션
     * @param userId 사용자 ID
     * @param resourceId 리소스 식별자
     */
    private void handleAnalysisRequirement(Protectable protectable, String userId, String resourceId) {
        AnalysisRequirement requirement = protectable.analysisRequirement();

        log.debug("[ZeroTrust] analysisRequirement 처리 - userId: {}, requirement: {}, resourceId: {}",
            userId, requirement, resourceId);

        switch (requirement) {
            case NOT_REQUIRED -> {
                // 분석 불필요 - 바로 통과
                log.debug("[ZeroTrust] NOT_REQUIRED - 분석 대기 없이 통과");
            }

            case PREFERRED -> {
                // 분석 있으면 사용, 없으면 defaultAction 사용
                String action = getCurrentAction(userId);
                if ("PENDING_ANALYSIS".equals(action)) {
                    String defaultAction = protectable.defaultAction();
                    log.debug("[ZeroTrust] PREFERRED - 분석 미완료, defaultAction 사용: {}", defaultAction);
                    // defaultAction이 BLOCK이면 거부
                    if ("BLOCK".equalsIgnoreCase(defaultAction)) {
                        throw ZeroTrustAccessDeniedException.blocked(resourceId, 0.5);
                    }
                    // 그 외는 통과 (ALLOW, MONITOR 등)
                } else {
                    // 분석 완료됨 - action 기반 판단
                    validateAction(action, resourceId);
                }
            }

            case REQUIRED -> {
                // 분석 완료 필수 (동기 대기)
                long timeoutMs = protectable.analysisTimeout();
                waitForAnalysis(userId, resourceId, timeoutMs);

                // 분석 완료 후 action 검증
                String action = getCurrentAction(userId);
                validateAction(action, resourceId);
            }

            case STRICT -> {
                // 분석 완료 + ALLOW action 필수
                long timeoutMs = protectable.analysisTimeout();
                waitForAnalysis(userId, resourceId, timeoutMs);

                // ALLOW만 허용
                String action = getCurrentAction(userId);
                if (!"ALLOW".equalsIgnoreCase(action)) {
                    log.warn("[ZeroTrust] STRICT 리소스에서 ALLOW가 아닌 action: {} - 거부", action);
                    throw new ZeroTrustAccessDeniedException(
                        action,
                        resourceId,
                        0.7,
                        "STRICT 리소스는 ALLOW action만 허용됨"
                    );
                }
            }
        }
    }

    /**
     * 분석 완료까지 대기 (동기)
     *
     * @param userId 사용자 ID
     * @param resourceId 리소스 식별자
     * @param timeoutMs 타임아웃 밀리초
     */
    private void waitForAnalysis(String userId, String resourceId, long timeoutMs) {
        long startTime = System.currentTimeMillis();

        while (true) {
            String action = getCurrentAction(userId);
            if (!"PENDING_ANALYSIS".equals(action)) {
                log.debug("[ZeroTrust] 분석 완료 - userId: {}, action: {}, 대기시간: {}ms",
                    userId, action, System.currentTimeMillis() - startTime);
                return;
            }

            // 타임아웃 체크
            if (System.currentTimeMillis() - startTime > timeoutMs) {
                log.warn("[ZeroTrust] 분석 타임아웃 - userId: {}, timeout: {}ms", userId, timeoutMs);
                throw ZeroTrustAccessDeniedException.analysisTimeout(resourceId, timeoutMs);
            }

            // 폴링 간격 대기
            try {
                Thread.sleep(POLLING_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ZeroTrustAccessDeniedException(
                    "PENDING_ANALYSIS",
                    resourceId,
                    0.5,
                    "분석 대기 중 인터럽트 발생"
                );
            }
        }
    }

    /**
     * action 유효성 검증
     *
     * BLOCK, CHALLENGE, INVESTIGATE, ESCALATE인 경우 예외 발생
     *
     * @param action LLM이 결정한 action
     * @param resourceId 리소스 식별자
     */
    private void validateAction(String action, String resourceId) {
        if (action == null || ALLOWED_ACTIONS.contains(action.toUpperCase())) {
            return; // ALLOW, MONITOR는 통과
        }

        switch (action.toUpperCase()) {
            case "BLOCK" -> throw ZeroTrustAccessDeniedException.blocked(resourceId, 0.8);
            case "CHALLENGE" -> throw ZeroTrustAccessDeniedException.challengeRequired(resourceId, 0.6);
            case "INVESTIGATE", "ESCALATE" -> throw ZeroTrustAccessDeniedException.pendingReview(resourceId, 0.7);
            default -> {
                log.warn("[ZeroTrust] 알 수 없는 action: {} - 거부", action);
                throw new ZeroTrustAccessDeniedException(
                    action,
                    resourceId,
                    0.5,
                    "알 수 없는 action: " + action
                );
            }
        }
    }

    /**
     * Redis에서 현재 action 조회 (Dual-Read)
     *
     * 조회 우선순위:
     * 1. Primary: security:hcad:analysis:{userId} Hash에서 action 필드
     * 2. Fallback: security:user:action:{userId} String
     * 3. 키 없음 -> PENDING_ANALYSIS
     *
     * @param userId 사용자 ID
     * @return action 문자열
     */
    private String getCurrentAction(String userId) {
        if (userId == null || userId.isEmpty()) {
            return "PENDING_ANALYSIS";
        }

        try {
            // 1. Primary: HCAD 분석 결과 Hash에서 조회
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object action = redisTemplate.opsForHash().get(analysisKey, "action");
            if (action != null) {
                return action.toString();
            }

            // 2. Fallback: 레거시 키 조회
            String legacyKey = ZeroTrustRedisKeys.userAction(userId);
            Object legacyAction = redisTemplate.opsForValue().get(legacyKey);
            if (legacyAction != null) {
                return legacyAction.toString();
            }

            // 3. 키 없음 -> PENDING_ANALYSIS
            return "PENDING_ANALYSIS";

        } catch (Exception e) {
            log.error("[ZeroTrust] action 조회 실패 - userId: {}", userId, e);
            return "PENDING_ANALYSIS";
        }
    }

    /**
     * 리소스 식별자 생성
     *
     * @param mi 메서드 호출 정보
     * @return 메서드 식별자 (클래스.메서드(파라미터타입))
     */
    private String getResourceId(MethodInvocation mi) {
        Method method = mi.getMethod();
        String paramTypes = Arrays.stream(method.getParameterTypes())
            .map(Class::getSimpleName)
            .collect(Collectors.joining(","));
        return method.getDeclaringClass().getName() + "." + method.getName() + "(" + paramTypes + ")";
    }

    /**
     * 인증 정보에서 사용자 ID 추출
     *
     * @param authentication 인증 정보
     * @return 사용자 ID (없으면 "anonymous")
     */
    private String extractUserId(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return "anonymous";
        }
        return authentication.getName();
    }

    // ============================================
    // 실시간 응답 차단 (enableRuntimeInterception) 처리
    // ============================================

    /**
     * 현재 요청에 대해 실시간 응답 차단 활성화
     *
     * ZeroTrustResponseInterceptor에 위임하여 플래그 설정
     */
    private void enableRuntimeInterception() {
        String requestId = getCurrentRequestId();
        if (requestId != null && zeroTrustResponseInterceptor != null) {
            zeroTrustResponseInterceptor.enableRuntimeInterception(requestId);
            log.debug("[ZeroTrust] 실시간 응답 차단 활성화 - requestId: {}", requestId);
        }
    }

    /**
     * 현재 요청 ID 조회
     *
     * ZeroTrustResponseFilter에서 설정한 요청 속성에서 조회
     *
     * @return 요청 ID (없으면 null)
     */
    private String getCurrentRequestId() {
        try {
            ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                Object requestId = request.getAttribute("zeroTrustRequestId");
                return requestId != null ? requestId.toString() : null;
            }
        } catch (Exception e) {
            log.debug("[ZeroTrust] 요청 ID 조회 실패", e);
        }
        return null;
    }
}