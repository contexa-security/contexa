package io.contexa.contexacore.hcad.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

/**
 * HCAD (Hyper-lightweight Context Anomaly Detector) 필터 (v3.0) - AI Native
 *
 * Spring Security 필터 체인에 통합되어 모든 요청을 실시간으로 검사
 *
 * AI Native 아키텍처:
 * - LLM이 Cold Path에서 분석한 결과를 Redis에서 조회 (1-5ms)
 * - 모든 판단(isAnomaly, riskScore, threatType)은 LLM이 결정
 * - HCADFilter는 LLM 결과를 조회하고 request attribute에 저장만 함
 * - 규칙 기반 임계값 판단 없음
 *
 * 요청 해시 캐싱 (v3.1):
 * - contextHash = hash(IP + UserAgent + Path + Method)
 * - 동일 요청 패턴에 대해 Redis 캐시 사용
 * - LLM 호출 최소화를 위한 성능 최적화
 *
 * 위치: SecurityContextHolderFilter 직후, UsernamePasswordAuthenticationFilter 이전
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
public class HCADFilter extends OncePerRequestFilter {

    private final HCADAnalysisService hcadAnalysisService;

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Value("${hcad.enabled:true}")
    private boolean enabled;

    @Value("${hcad.cache.ttl-seconds:60}")
    private long cacheTtlSeconds;

    @Value("${hcad.cache.max-size:10000}")
    private long cacheMaxSize;

    @Value("${hcad.cache.enabled:true}")
    private boolean cacheEnabled;

    /**
     * Phase 3: Caffeine 로컬 캐시 (Redis 대체)
     *
     * 설계 근거:
     * - Redis 메모리 폭발 해결 (수억 키 -> 인스턴스당 최대 10,000개)
     * - 계정 탈취 탐지를 위해 전체 컨텍스트(IP + UA + Path + Method) 포함
     * - 분산 환경 일관성 문제는 있지만, "중복 분석 방지" 목적으로 충분
     *
     * 캐시 키: contextHash = SHA-256(IP + UA + Path + Method)
     * 캐시 용도: HCAD 분석 중복 방지 (성능 최적화) - 이벤트 발행과 무관
     */
    private Cache<String, HCADAnalysisResult> localCache;

    public HCADFilter(HCADAnalysisService hcadAnalysisService) {
        this.hcadAnalysisService = hcadAnalysisService;
    }

    @PostConstruct
    public void init() {
        // Caffeine 캐시 초기화 (JVM 시작 후 설정값으로)
        this.localCache = Caffeine.newBuilder()
                .maximumSize(cacheMaxSize)
                .expireAfterWrite(cacheTtlSeconds, TimeUnit.SECONDS)
                .recordStats()  // 캐시 통계 기록 (모니터링용)
                .build();

        log.info("[HCAD][AI Native][Phase 3] Filter initialized with Caffeine local cache - " +
                "enabled: {}, cacheEnabled: {}, cacheTtlSeconds: {}, cacheMaxSize: {}",
            enabled, cacheEnabled, cacheTtlSeconds, cacheMaxSize);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // HCAD 가 비활성화되어 있으면 통과
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = this.trustResolver.isAuthenticated(authentication);

        if (!enabled || !isAuthenticated) {
            filterChain.doFilter(request, response);
            return;
        }

        request.setAttribute("hcad.is_authenticated", isAuthenticated);

        try {
            // 1. 요청 해시 생성 (IP + UserAgent + Path + Method)
            String contextHash = generateContextHash(request);

            // 2. 캐시 확인 (동일 요청 패턴이면 캐시된 결과 사용)
            HCADAnalysisResult result = getCachedResult(contextHash);
            boolean fromCache = (result != null);

            if (result == null) {
                // 3. 캐시 미스: HCAD 분석 수행
                result = hcadAnalysisService.analyze(request, authentication);

                // 4. 결과 캐싱 (LLM 호출 최소화)
                cacheResult(contextHash, result);
            }

            // 5. request attribute에 저장 (SecurityEventPublishingFilter 에서 재사용)
            // AI Native: 모든 값은 LLM이 판단한 결과 (Redis에서 조회)
            request.setAttribute("hcad.trust_score", result.getTrustScore());
            request.setAttribute("hcad.threat_type", result.getThreatType());
            request.setAttribute("hcad.threat_evidence", result.getThreatEvidence());
            request.setAttribute("hcad.is_anomaly", result.isAnomaly());
            request.setAttribute("hcad.risk_score", result.getAnomalyScore());
            request.setAttribute("hcad.action", result.getAction());  // AI Native: LLM이 결정한 action
            request.setAttribute("hcad.confidence", result.getConfidence());  // AI Native: LLM이 결정한 confidence
            request.setAttribute("hcad.from_cache", fromCache);

            // 5-1. 세션/사용자 컨텍스트 정보 저장 (Phase 9: Layer1 프롬프트 강화)
            // HCADContext에서 추출한 세션/사용자 상태 정보를 Layer1PromptTemplate에서 활용
            if (result.getContext() != null) {
                request.setAttribute("hcad.is_new_session", result.getContext().getIsNewSession());
                request.setAttribute("hcad.is_new_user", result.getContext().getIsNewUser());
                request.setAttribute("hcad.is_new_device", result.getContext().getIsNewDevice());
                request.setAttribute("hcad.recent_request_count", result.getContext().getRecentRequestCount());
            }

            if (log.isDebugEnabled()) {
                log.debug("[HCADFilter] 분석 완료 (fromCache={}): contextHash={}, action={}, riskScore={}",
                    fromCache, contextHash.substring(0, 8), result.getAction(), String.format("%.3f", result.getAnomalyScore()));
            }

            // 6. action 기반 로그 기록 (AI Native: LLM이 action을 직접 결정)
            String action = result.getAction();
            if ("BLOCK".equalsIgnoreCase(action) || "ESCALATE".equalsIgnoreCase(action)) {
                log.warn("[HCADFilter][AI Native] Security action: {} - userId: {}, riskScore: {}, threatType: {}",
                    action, result.getUserId(), String.format("%.3f", result.getAnomalyScore()), result.getThreatType());
            }

            // 요청 통과
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("[HCAD] 처리 중 오류 발생", e);
            // 오류 발생 시 안전하게 통과 (fail-open)
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 정적 리소스, 헬스체크, 메트릭 수집 경로는 필터링하지 않음
        String path = request.getRequestURI();
        return path.startsWith("/static/") ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.equals("/health") ||
               path.startsWith("/actuator/") ||
               path.startsWith("/api/admin/test/vectorstore");
    }

    /**
     * 요청 컨텍스트 해시 생성
     *
     * contextHash = SHA-256(IP + UserAgent + Path + Method)
     * 동일한 요청 패턴을 식별하여 캐싱에 활용
     *
     * @param request HTTP 요청
     * @return 컨텍스트 해시 문자열
     */
    private String generateContextHash(HttpServletRequest request) {
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) {
            userAgent = "unknown";
        }
        String path = request.getRequestURI();
        String method = request.getMethod();

        String contextString = ip + "|" + userAgent + "|" + path + "|" + method;

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(contextString.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256은 항상 사용 가능하므로 발생하지 않음
            log.error("[HCADFilter] SHA-256 알고리즘 사용 불가", e);
            return String.valueOf(contextString.hashCode());
        }
    }

    /**
     * 클라이언트 IP 추출 (프록시 헤더 고려)
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // X-Forwarded-For는 콤마로 구분된 IP 목록일 수 있음 (첫 번째가 클라이언트 IP)
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip != null ? ip : "unknown";
    }

    /**
     * 캐시된 분석 결과 조회 (Phase 3: Caffeine 로컬 캐시)
     *
     * 캐시 용도: HCAD 분석 중복 방지 (성능 최적화)
     * 캐시 키: contextHash = SHA-256(IP + UA + Path + Method)
     *
     * CRITICAL: 캐시 히트/미스는 이벤트 발행과 무관
     * - 이벤트 발행은 SecurityEventPublishingFilter에서 별도 정책으로 결정
     *
     * @param contextHash 요청 컨텍스트 해시
     * @return 캐시된 HCADAnalysisResult (없으면 null)
     */
    private HCADAnalysisResult getCachedResult(String contextHash) {
        if (!cacheEnabled || localCache == null) {
            return null;
        }

        try {
            HCADAnalysisResult cached = localCache.getIfPresent(contextHash);
            if (cached != null && log.isDebugEnabled()) {
                log.debug("[HCADFilter][Caffeine] Cache HIT: contextHash={}", contextHash.substring(0, 8));
            }
            return cached;
        } catch (Exception e) {
            log.debug("[HCADFilter][Caffeine] Cache lookup failed: contextHash={}", contextHash.substring(0, 8), e);
        }
        return null;
    }

    /**
     * 분석 결과 캐싱 (Phase 3: Caffeine 로컬 캐시)
     *
     * 설계 근거:
     * - Redis 메모리 폭발 해결 (인스턴스당 최대 10,000개 키)
     * - LRU 자동 삭제로 메모리 한도 내 관리
     * - 동일 요청 반복 시 HCAD 분석 스킵 (성능 최적화)
     *
     * @param contextHash 요청 컨텍스트 해시
     * @param result HCAD 분석 결과
     */
    private void cacheResult(String contextHash, HCADAnalysisResult result) {
        if (!cacheEnabled || localCache == null) {
            return;
        }

        try {
            localCache.put(contextHash, result);

            if (log.isDebugEnabled()) {
                log.debug("[HCADFilter][Caffeine] Cache PUT: contextHash={}, estimatedSize={}",
                    contextHash.substring(0, 8), localCache.estimatedSize());
            }
        } catch (Exception e) {
            log.debug("[HCADFilter][Caffeine] Cache put failed: contextHash={}", contextHash.substring(0, 8), e);
        }
    }
}