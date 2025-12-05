package io.contexa.contexacore.autonomous.filter;

import io.contexa.contexacore.autonomous.interceptor.ZeroTrustResponseInterceptor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Zero Trust 응답 컨텍스트 등록 필터
 *
 * SecurityFilterChain 직후에 실행되어 응답 컨텍스트를 등록한다.
 * LLM 분석이 완료되면 ZeroTrustResponseInterceptor에서 실시간 차단이 가능해진다.
 *
 * 필터 순서:
 * 1. SecurityFilterChain (인증/인가)
 * 2. ZeroTrustResponseFilter (응답 컨텍스트 등록)
 * 3. 기타 비즈니스 필터
 * 4. DispatcherServlet
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
@RequiredArgsConstructor
@Slf4j
public class ZeroTrustResponseFilter extends OncePerRequestFilter {

    private final ZeroTrustResponseInterceptor interceptor;

    /**
     * 요청 ID 헤더명
     */
    public static final String REQUEST_ID_HEADER = "X-ZeroTrust-Request-Id";

    /**
     * 요청 속성명 (다른 컴포넌트에서 접근용)
     */
    public static final String REQUEST_ID_ATTRIBUTE = "zeroTrustRequestId";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 요청 ID 생성 (기존 헤더 있으면 재사용)
        String requestId = request.getHeader(REQUEST_ID_HEADER);
        if (requestId == null || requestId.isEmpty()) {
            requestId = generateRequestId();
        }

        // 요청 속성에 저장 (다른 컴포넌트에서 접근 가능)
        request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);

        // 응답 헤더에도 추가 (클라이언트 추적용)
        response.setHeader(REQUEST_ID_HEADER, requestId);

        try {
            // 응답 컨텍스트 등록
            interceptor.registerResponse(requestId, response);

            log.debug("[ZeroTrustFilter] 요청 처리 시작: requestId={}, uri={}",
                requestId, request.getRequestURI());

            // 다음 필터 체인 실행
            filterChain.doFilter(request, response);

        } finally {
            // 항상 해제 (메모리 누수 방지)
            interceptor.unregisterResponse(requestId);

            // 실시간 응답 차단 플래그도 해제 (Phase 8)
            interceptor.clearRuntimeInterception(requestId);

            log.debug("[ZeroTrustFilter] 요청 처리 완료: requestId={}", requestId);
        }
    }

    /**
     * 필터 적용 여부 결정
     *
     * 정적 리소스 및 헬스체크 경로는 제외
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // 정적 리소스 제외
        if (path.startsWith("/static/") ||
            path.startsWith("/css/") ||
            path.startsWith("/js/") ||
            path.startsWith("/images/") ||
            path.startsWith("/favicon.ico")) {
            return true;
        }

        // 헬스체크 및 메트릭 제외
        if (path.startsWith("/actuator/") ||
            path.equals("/health") ||
            path.equals("/ready") ||
            path.equals("/live")) {
            return true;
        }

        return false;
    }

    /**
     * 고유 요청 ID 생성
     *
     * 형식: zt-{timestamp}-{uuid}
     *
     * @return 요청 ID
     */
    private String generateRequestId() {
        return String.format("zt-%d-%s",
            System.currentTimeMillis(),
            UUID.randomUUID().toString().substring(0, 8));
    }

    /**
     * 현재 요청의 requestId 조회
     *
     * @param request HTTP 요청
     * @return 요청 ID (없으면 null)
     */
    public static String getRequestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return requestId != null ? requestId.toString() : null;
    }
}
