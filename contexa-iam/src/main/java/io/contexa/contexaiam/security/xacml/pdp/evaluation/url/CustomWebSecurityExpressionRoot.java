package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.List;

@Slf4j
public class CustomWebSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private final HttpServletRequest request;

    public CustomWebSecurityExpressionRoot(Authentication authentication, HttpServletRequest request,
                                           AuthorizationContext authorizationContext,
                                           AuditLogRepository auditLogRepository) {
        super(authentication, authorizationContext, auditLogRepository);
        this.request = request;

    }

    public boolean hasIpAddress(String ipAddress) {
        IpAddressMatcher matcher = new IpAddressMatcher(ipAddress);
        return matcher.matches(this.request);
    }


    @Override
    protected String getCurrentAction() {
        return request.getMethod();
    }
}