package io.contexa.contexaiam.security.core.session;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 세션 ID 추출 전략 인터페이스
 *
 * Spring Session의 Redis 세션 ID를 다양한 소스에서 추출하는 전략을 정의합니다.
 * HttpSession ID가 아닌 실제 Redis에 저장된 세션 ID를 추출합니다.
 *
 * @author contexa
 * @since 1.0
 */
public interface SessionIdResolver {

    /**
     * HTTP 요청에서 Redis 세션 ID를 추출합니다.
     *
     * 추출 우선순위:
     * 1. SESSION 쿠키 (Spring Session 기본)
     * 2. X-Auth-Token 헤더 (API 클라이언트)
     * 3. Authorization 헤더의 Bearer 토큰
     * 4. Request Attribute (Spring Session 내부)
     *
     * @param request HTTP 요청
     * @return Redis 세션 ID, 없으면 null
     */
    String resolve(HttpServletRequest request);

    /**
     * 세션 ID 유효성 검증
     *
     * @param sessionId 검증할 세션 ID
     * @return 유효하면 true
     */
    boolean isValid(String sessionId);

    /**
     * 세션 ID 소스 타입 반환
     *
     * @param request HTTP 요청
     * @return 세션 ID 소스 (COOKIE, HEADER, ATTRIBUTE, NONE)
     */
    SessionSource getSource(HttpServletRequest request);

    /**
     * 세션 ID 소스 타입
     */
    enum SessionSource {
        COOKIE("Cookie에서 추출"),
        HEADER("HTTP Header에서 추출"),
        ATTRIBUTE("Request Attribute에서 추출"),
        BEARER("Bearer Token에서 추출"),
        NONE("세션 ID 없음");

        private final String description;

        SessionSource(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}