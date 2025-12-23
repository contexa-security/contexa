package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.RequiredArgsConstructor;
import java.util.List;

@RequiredArgsConstructor
public class DefaultRiskEngine implements RiskEngine {

    private final List<RiskFactorEvaluator> evaluators;

    /**
     * AI Native v3.3.0: 규칙 기반 점수 계산 제거
     *
     * LLM이 직접 위험 수준을 판단해야 함
     * 이 메서드는 하위 호환성을 위해 유지되나, 0을 반환
     * 실제 위험 평가는 SecurityDecision.action 기반으로 처리
     */
    @Override
    public int calculateRiskScore(AuthorizationContext context) {
        // AI Native: 규칙 기반 점수 합산 제거
        // LLM이 SecurityDecision.action으로 직접 판단
        return 0;
    }
}