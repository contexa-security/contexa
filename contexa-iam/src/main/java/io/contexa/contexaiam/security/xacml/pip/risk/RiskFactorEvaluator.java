package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;

public interface RiskFactorEvaluator {
    /**
     * [최종 수정] 표준 인가 컨텍스트를 받아 리스크 요인을 평가합니다.
     * @param context 평가에 필요한 모든 정보가 담긴 컨텍스트
     * @return 해당 요인의 리스크 점수
     */
    int evaluate(AuthorizationContext context);
}
