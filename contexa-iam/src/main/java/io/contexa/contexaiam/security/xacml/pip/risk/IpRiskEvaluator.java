package io.contexa.contexaiam.security.xacml.pip.risk;

import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.annotation.Order;
import java.util.Set;

@Order(10)
public class IpRiskEvaluator implements RiskFactorEvaluator {
    private static final Set<String> TRUSTED_IPS = Set.of("127.0.0.1", "0:0:0:0:0:0:0:1");

    @Override
    public int evaluate(AuthorizationContext context) {
        final HttpServletRequest request = context.environment().request();

        if (request != null) {
            final String remoteIp = request.getRemoteAddr();
            if (!TRUSTED_IPS.contains(remoteIp)) {
                return 30; 
            }
            return 0; 
        } else {
            
            return 15;
        }
    }
}