package io.contexa.contexaidentity.security.core.mfa.context;

import jakarta.servlet.http.HttpServletRequest;

/**
 * FactorContext를 저장, 로드, 삭제하는 방법을 정의하는 인터페이스.
 * 구현체는 HTTP 세션, 데이터베이스, Redis 등 다양한 저장소를 사용할 수 있습니다.
 */
public interface FactorContextManager {
    /**
     * 주어진 요청에서 FactorContext를 로드합니다.
     * 컨텍스트가 존재하지 않으면 null을 반환할 수 있습니다.
     * @param req HttpServletRequest
     * @return 저장된 FactorContext 또는 null
     */
    FactorContext load(HttpServletRequest req);

    /**
     * 주어진 FactorContext를 저장소에 저장합니다.
     * @param ctx 저장할 FactorContext
     * @param req HttpServletRequest (세션 등에 접근하기 위해 필요할 수 있음)
     */
    void save(FactorContext ctx, HttpServletRequest req);

    /**
     * 주어진 요청과 관련된 FactorContext를 저장소에서 삭제합니다.
     * @param req HttpServletRequest
     */
    void clear(HttpServletRequest req);
}


