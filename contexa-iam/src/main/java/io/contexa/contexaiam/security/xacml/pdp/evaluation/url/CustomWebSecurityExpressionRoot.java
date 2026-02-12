package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

@Slf4j
public class CustomWebSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private final HttpServletRequest request;

    public CustomWebSecurityExpressionRoot(Authentication authentication, HttpServletRequest request,
                                           AuthorizationContext authorizationContext,
                                           AuditLogRepository auditLogRepository,
                                           ZeroTrustActionRedisRepository actionRedisRepository) {
        super(authentication, authorizationContext, auditLogRepository, actionRedisRepository);
        this.request = request;
    }

    public boolean hasIpAddress(String ipAddress) {
        IpAddressMatcher matcher = new IpAddressMatcher(ipAddress);
        return matcher.matches(this.request);
    }

    public String getHttpMethod() {
        return request.getMethod();
    }
}