package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

@Slf4j
public class CustomWebSecurityExpressionHandler extends DefaultHttpSecurityExpressionHandler {

    private final ContextHandler contextHandler;
    private final AuditLogRepository auditLogRepository;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final RoleHierarchy roleHierarchy;

    public CustomWebSecurityExpressionHandler(ContextHandler contextHandler,
                                              AuditLogRepository auditLogRepository,
                                              ZeroTrustActionRepository actionRedisRepository,
                                              RoleHierarchy roleHierarchy) {
        this.contextHandler = contextHandler;
        this.auditLogRepository = auditLogRepository;
        this.actionRedisRepository = actionRedisRepository;
        this.roleHierarchy = roleHierarchy;
        super.setRoleHierarchy(roleHierarchy);
    }

    @Override
    public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, RequestAuthorizationContext requestContext) {

        Authentication auth = authentication.get();
        HttpServletRequest request = requestContext.getRequest();

        AuthorizationContext authorizationContext = contextHandler.create(auth, request);

        CustomWebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(auth, request, authorizationContext, auditLogRepository, actionRedisRepository);

        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(new AuthenticationTrustResolverImpl());
        root.setRoleHierarchy(roleHierarchy);
        root.setDefaultRolePrefix("ROLE_");

        StandardEvaluationContext ctx = new StandardEvaluationContext(root);
        ctx.setBeanResolver(getBeanResolver());

        ctx.setVariable("ai", root);

        requestContext.getVariables().forEach(ctx::setVariable);

        return ctx;
    }
}