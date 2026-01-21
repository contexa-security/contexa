package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext; 

public interface RiskEngine {
    
    int calculateRiskScore(AuthorizationContext context);
}