package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext; // AuthorizationContext 임포트

/**
 * [최종 수정] 요청의 위험도를 평가하는 책임을 가지며,
 * 이제 HttpServletRequest가 아닌 표준 AuthorizationContext를 기반으로 동작합니다.
 */
public interface RiskEngine {
    /**
     * 주어진 표준 인가 컨텍스트를 기반으로 위험도 점수를 계산합니다.
     * @param context 현재 인가 컨텍스트 (내부에 Authentication, Optional<HttpServletRequest> 등을 포함)
     * @return 위험도 점수 (예: 0-100, 낮을수록 안전)
     */
    int calculateRiskScore(AuthorizationContext context);
}