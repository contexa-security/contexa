package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * HCAD 컨텍스트 추출 서비스
 *
 * HTTP 요청과 인증 정보에서 HCAD 분석에 필요한 컨텍스트를 추출
 * 성능 목표: 1-5ms
 */
@Slf4j
@RequiredArgsConstructor
public class HCADContextExtractor {

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * 요청에서 HCAD 컨텍스트 추출
     *
     * 익명 사용자 처리 개선:
     * - 익명 사용자는 IP 주소를 기반으로 userId 생성 (anonymous:{IP})
     * - 이를 통해 익명 사용자별 행동 패턴 학습 및 유사도 계산 가능
     */
    public HCADContext extractContext(HttpServletRequest request, Authentication authentication) {
        long startTime = System.nanoTime();

        try {
            // IP 주소 먼저 추출 (익명 사용자 userId에 필요)
            String clientIp = extractClientIp(request);

            // userId 추출 - Principal이 UserDto일 수 있음을 고려
            String userId = extractUserId(authentication);
            String username = extractUsername(authentication);
            String sessionId = request.getRequestedSessionId();

            // 익명 사용자는 IP 주소를 userId로 사용
            if (userId.startsWith("anonymous:")) {
                userId = "anonymous:" + clientIp;
                username = "anonymous:" + clientIp;
            }

            // 기본 정보 추출
            HCADContext context = new HCADContext();
            context.setUserId(userId);
            context.setSessionId(sessionId);
            context.setUsername(username);
            context.setRequestPath(request.getRequestURI());
            context.setHttpMethod(request.getMethod());
            context.setRemoteIp(clientIp);
            // 테스트용 X-Simulated-User-Agent 헤더 우선 읽기 (브라우저 보안 정책으로 User-Agent 직접 수정 불가)
            String userAgent = request.getHeader("X-Simulated-User-Agent");
            if (userAgent == null || userAgent.isEmpty()) {
                userAgent = request.getHeader("User-Agent");
            }
            context.setUserAgent(userAgent);
            context.setReferer(request.getHeader("Referer"));
            context.setTimestamp(Instant.now());

            // 세션 정보 확인
            enrichWithSessionInfo(context, userId, sessionId);

            // 요청 패턴 분석
            enrichWithRequestPattern(context, userId, request);

            // 보안 정보 추가
            enrichWithSecurityInfo(context, userId, authentication);

            // 리소스 정보 분석
            enrichWithResourceInfo(context, request);

            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            log.debug("[HCAD] 컨텍스트 추출 완료: {}ms", elapsedMs);

            return context;

        } catch (Exception e) {
            log.error("[HCAD] 컨텍스트 추출 실패", e);
            // 최소한의 컨텍스트 반환
            return HCADContext.builder()
                .userId(authentication != null ? extractUserId(authentication) : "unknown")
                .sessionId(request.getRequestedSessionId())
                .requestPath(request.getRequestURI())
                .httpMethod(request.getMethod())
                .remoteIp(request.getRemoteAddr())
                .timestamp(Instant.now())
                .build();
        }
    }

    /**
     * Authentication 에서 userId 추출
     * Principal이 UserDto 객체일 경우를 처리
     * 익명 사용자 처리 개선:
     * - 익명 사용자는 "anonymous:{IP}" 형식으로 userId 생성
     * - 이를 통해 익명 사용자도 HCAD 유사도 계산 및 패턴 학습 가능
     */
    private String extractUserId(Authentication authentication) {
        if (authentication == null) {
            return "anonymous:unknown";
        }

        Object principal = authentication.getPrincipal();

        // 익명 사용자 판별 (Spring Security의 anonymousUser)
        if ("anonymousUser".equals(principal)) {
            return "anonymous:" + System.currentTimeMillis(); // 임시 ID (나중에 IP로 대체)
        }

        // UserDto의 username 필드 추출 (리플렉션 사용)
        if (principal != null && principal.getClass().getSimpleName().contains("UserDto")) {
            try {
                // username 필드 가져오기
                java.lang.reflect.Method getUsernameMethod = principal.getClass().getMethod("getUsername");
                Object username = getUsernameMethod.invoke(principal);
                return username != null ? username.toString() : authentication.getName();
            } catch (Exception e) {
                log.debug("[HCAD] UserDto에서 username 추출 실패, getName() 사용", e);
                return authentication.getName();
            }
        }

        // 기본 처리
        String name = authentication.getName();

        // anonymousUser인 경우 처리
        if ("anonymousUser".equals(name)) {
            return "anonymous:" + System.currentTimeMillis(); // 임시 ID (나중에 IP로 대체)
        }

        return name;
    }

    /**
     * Authentication에서 username 추출
     */
    private String extractUsername(Authentication authentication) {
        return extractUserId(authentication); // 동일한 로직 사용
    }

    /**
     * 실제 클라이언트 IP 추출 (프록시 고려)
     */
    private String extractClientIp(HttpServletRequest request) {
        String[] headers = {
            "X-Forwarded-For",
            "X-Real-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // 여러 IP가 있는 경우 첫 번째 선택
                if (ip.contains(",")) {
                    return ip.split(",")[0].trim();
                }
                return ip.trim();
            }
        }

        return request.getRemoteAddr();
    }

    /**
     * 세션 관련 정보 추가
     */
    private void enrichWithSessionInfo(HCADContext context,
                                      String userId, String sessionId) {
        try {
            // 세션 정보 키
            String sessionKey = "session:info:" + sessionId;
            Map<Object, Object> sessionInfo = redisTemplate.opsForHash().entries(sessionKey);

            if (sessionInfo != null && !sessionInfo.isEmpty()) {
                // 기존 세션
                context.setIsNewSession(false);

                // 이전 디바이스 정보와 비교
                String lastDevice = (String) sessionInfo.get("device");
                String currentDevice = context.getUserAgent();
                context.setIsNewDevice(!currentDevice.equals(lastDevice));

            } else {
                // 새 세션
                context.setIsNewSession(true);
                context.setIsNewDevice(true);

                // 세션 정보 저장
                Map<String, Object> newSessionInfo = new HashMap<>();
                newSessionInfo.put("userId", userId);
                newSessionInfo.put("device", context.getUserAgent());
                newSessionInfo.put("createdAt", Instant.now().toString());
                redisTemplate.opsForHash().putAll(sessionKey, newSessionInfo);
                redisTemplate.expire(sessionKey, Duration.ofHours(24));
            }

        } catch (Exception e) {
            log.debug("[HCAD] 세션 정보 추출 실패", e);
            context.setIsNewSession(true);
            context.setIsNewDevice(true);
        }
    }

    /**
     * 요청 패턴 정보 추가
     */
    private void enrichWithRequestPattern(HCADContext context,
                                         String userId, HttpServletRequest request) {
        try {
            // 최근 요청 카운터 키
            String counterKey = "hcad:request:counter:" + userId;

            // 현재 요청 기록
            long currentTime = System.currentTimeMillis();
            redisTemplate.opsForZSet().add(counterKey, Long.toString(currentTime), currentTime);

            // 5분 전 시간
            long fiveMinutesAgo = currentTime - (5 * 60 * 1000);

            // 오래된 엔트리 제거
            redisTemplate.opsForZSet().removeRangeByScore(counterKey, 0, fiveMinutesAgo);

            // 최근 5분간 요청 수
            Long recentCount = redisTemplate.opsForZSet().count(counterKey, fiveMinutesAgo, currentTime);
            context.setRecentRequestCount(recentCount != null ? recentCount.intValue() : 1);

            // 이전 요청과의 시간 간격
            String lastRequestKey = "hcad:last:request:" + userId;
            String lastRequestTime = (String) redisTemplate.opsForValue().get(lastRequestKey);
            if (lastRequestTime != null) {
                long interval = currentTime - Long.parseLong(lastRequestTime);
                context.setLastRequestInterval(interval);
            } else {
                context.setLastRequestInterval(0L);
            }

            // 현재 시간 저장
            redisTemplate.opsForValue().set(lastRequestKey, Long.toString(currentTime),
                Duration.ofMinutes(10));

            // 이전 경로 저장
            String previousPathKey = "hcad:previous:path:" + userId;
            String previousPath = (String) redisTemplate.opsForValue().get(previousPathKey);
            context.setPreviousPath(previousPath);
            redisTemplate.opsForValue().set(previousPathKey, request.getRequestURI(),
                Duration.ofMinutes(10));

        } catch (Exception e) {
            log.debug("[HCAD] 요청 패턴 정보 추출 실패", e);
            context.setRecentRequestCount(0);
            context.setLastRequestInterval(0L);
        }
    }

    /**
     * 보안 관련 정보 추가 (AI Native)
     *
     * AI Native 전환:
     * - 0.5 기본값 규칙 제거
     * - Redis에 값이 없으면 null로 표시 (LLM이 컨텍스트로 판단)
     * - isNewUser: 이전 HCAD 분석 기록이 없는 신규 사용자 판별
     */
    private void enrichWithSecurityInfo(HCADContext context,
                                       String userId, Authentication authentication) {
        try {
            // AI Native: 신규 사용자 판별 (이전 HCAD 분석 기록 확인)
            // LLM 분석 결과가 Redis에 저장되어 있으면 기존 사용자
            // security:hcad:analysis:{userId} 키에 LLM 분석 결과가 저장됨
            String analysisKey = "security:hcad:analysis:" + userId;
            Boolean hasAnalysis = redisTemplate.hasKey(analysisKey);
            context.setNewUser(!Boolean.TRUE.equals(hasAnalysis));

            // 신규 사용자는 Cold Path에서 LLM 분석 후 자동으로 기록됨
            if (Boolean.TRUE.equals(hasAnalysis)) {
                log.debug("[HCAD][AI Native] Known user (has analysis): {}", userId);
            } else {
                log.debug("[HCAD][AI Native] New user (no analysis yet): {}", userId);
            }

            // AI Native: 신뢰 점수를 그대로 조회 (기본값 규칙 제거)
            String trustScoreKey = "trust:score:" + userId;
            Double trustScore = (Double) redisTemplate.opsForValue().get(trustScoreKey);
            // AI Native: null이면 NaN으로 설정 (LLM이 "신뢰 정보 없음" 컨텍스트로 처리)
            context.setCurrentTrustScore(trustScore != null ? trustScore : Double.NaN);

            // AI Native: Baseline 신뢰도도 NaN으로 초기화 (LLM이 판단)
            context.setBaselineConfidence(Double.NaN);

            // 실패한 로그인 시도 조회 (원시 데이터)
            String failedLoginKey = "security:failed:login:" + userId;
            String failedCount = (String) redisTemplate.opsForValue().get(failedLoginKey);
            context.setFailedLoginAttempts(failedCount != null ? Integer.parseInt(failedCount) : 0);

            // 인증 방법 확인 (원시 데이터 - 규칙 아님)
            String authMethod = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().contains("MFA")) ? "mfa" : "password";
            context.setAuthenticationMethod(authMethod);

            // MFA 상태 확인 (원시 데이터)
            String mfaKey = "security:mfa:verified:" + userId;
            Boolean hasMfa = redisTemplate.hasKey(mfaKey);
            context.setHasValidMFA(hasMfa);

        } catch (Exception e) {
            log.debug("[HCAD][AI Native] 보안 정보 추출 실패", e);
            // AI Native: 예외 발생 시 NaN으로 설정 (분석 불가 상태 명시)
            context.setCurrentTrustScore(Double.NaN);
            context.setBaselineConfidence(Double.NaN);
            context.setFailedLoginAttempts(0);
            context.setHasValidMFA(false);
            context.setNewUser(true); // 오류 시 신규 사용자로 취급 (보수적 접근)
        }
    }

    /**
     * 리소스 정보 분석 (AI Native)
     *
     * AI Native 전환:
     * - 리소스 타입 분류 규칙 제거 (startsWith 규칙)
     * - 민감 리소스 판단 규칙 제거 (contains 규칙)
     * - 원시 경로 정보만 저장하여 LLM이 컨텍스트로 판단
     */
    private void enrichWithResourceInfo(HCADContext context,
                                       HttpServletRequest request) {
        try {
            String path = request.getRequestURI();

            // AI Native: 리소스 타입 분류 규칙 제거
            // 경로를 그대로 저장하여 LLM이 판단
            // resourceType 필드에는 경로의 첫 번째 세그먼트를 원시 데이터로 저장
            String[] segments = path.split("/");
            String firstSegment = segments.length > 1 ? segments[1] : "";
            context.setResourceType(firstSegment); // 원시 경로 세그먼트 (분류하지 않음)

            // AI Native: 민감 리소스 판단 규칙 제거
            // LLM이 경로 컨텍스트를 분석하여 민감도 판단
            // isSensitiveResource 필드는 null로 설정 (LLM이 판단)
            context.setIsSensitiveResource(null);

            // 추가 속성 (원시 데이터 수집)
            Map<String, Object> additionalAttrs = new HashMap<>();
            additionalAttrs.put("contentType", request.getContentType());
            additionalAttrs.put("queryString", request.getQueryString());
            additionalAttrs.put("protocol", request.getProtocol());
            additionalAttrs.put("secure", request.isSecure());
            additionalAttrs.put("fullPath", path); // AI Native: 전체 경로를 LLM 컨텍스트로 전달
            context.setAdditionalAttributes(additionalAttrs);

        } catch (Exception e) {
            log.debug("[HCAD][AI Native] 리소스 정보 추출 실패", e);
            context.setResourceType(null);
            context.setIsSensitiveResource(null);
        }
    }
}