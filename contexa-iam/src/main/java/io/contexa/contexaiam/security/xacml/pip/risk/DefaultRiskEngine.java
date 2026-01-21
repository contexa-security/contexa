package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.RequiredArgsConstructor;
import java.util.List;

@RequiredArgsConstructor
public class DefaultRiskEngine implements RiskEngine {

    private final List<RiskFactorEvaluator> evaluators;

    @Override
    public int calculateRiskScore(AuthorizationContext context) {

        return 0;
    }
}