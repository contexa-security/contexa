package io.contexa.contexacore.infra.session.generator;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;

/**
 * MFA 세션 ID 생성 전략 인터페이스
 */
public interface SessionIdGenerator {

    /**
     * 고유한 세션 ID를 생성합니다.
     *
     * @param baseId 기본 ID (선택적)
     * @param request HTTP 요청
     * @return 생성된 고유 세션 ID
     */
    String generate(@Nullable String baseId, HttpServletRequest request);

    /**
     * 세션 ID 형식이 유효한지 검증합니다.
     *
     * @param sessionId 검증할 세션 ID
     * @return 유효하면 true
     */
    boolean isValidFormat(String sessionId);

    /**
     * 충돌 해결을 위한 새로운 세션 ID를 생성합니다.
     *
     * @param originalId 원본 ID
     * @param attempt 시도 횟수
     * @param request HTTP 요청
     * @return 충돌 해결된 세션 ID
     */
    String resolveCollision(String originalId, int attempt, HttpServletRequest request);
}
