package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;

public interface RiskFactorEvaluator {
    
    int evaluate(AuthorizationContext context);
}
