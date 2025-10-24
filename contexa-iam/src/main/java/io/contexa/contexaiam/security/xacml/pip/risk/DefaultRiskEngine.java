package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
@RequiredArgsConstructor
public class DefaultRiskEngine implements RiskEngine {

    private final List<RiskFactorEvaluator> evaluators;

    /**
     * [최종 수정] calculateRiskScore의 시그니처가 변경되었습니다.
     */
    @Override
    public int calculateRiskScore(AuthorizationContext context) {
        // 주입받은 모든 평가 전략을 순회하며 점수를 합산
        return evaluators.stream()
                .mapToInt(evaluator -> evaluator.evaluate(context))
                .sum();
    }
}