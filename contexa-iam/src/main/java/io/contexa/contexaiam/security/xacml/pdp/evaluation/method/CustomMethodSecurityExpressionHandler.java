package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
public class CustomMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final ContextHandler contextHandler;
    private final AuditLogService auditLogService;
    private final AuditLogRepository auditLogRepository;
    private final ApplicationContext applicationContext;
    private final StringRedisTemplate stringRedisTemplate;

    public CustomMethodSecurityExpressionHandler(
            @Value("${security.zerotrust.mode:TRUST}") String zeroTrustMode,
            CustomPermissionEvaluator customPermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogService auditLogService,
            AuditLogRepository auditLogRepository,
            ApplicationContext applicationContext,
            StringRedisTemplate stringRedisTemplate) {
        Assert.notNull(policyRetrievalPoint, "PolicyRetrievalPoint cannot be null");
        Assert.notNull(zeroTrustMode, "zeroTrustMode cannot be null");

        this.policyRetrievalPoint = policyRetrievalPoint;
        this.contextHandler = contextHandler;
        this.auditLogService = auditLogService;
        this.auditLogRepository = auditLogRepository;
        this.applicationContext = applicationContext;
        this.stringRedisTemplate = stringRedisTemplate;
        super.setPermissionEvaluator(customPermissionEvaluator);
        super.setRoleHierarchy(roleHierarchy);

    }

    @Override
    public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) {

        String ownerField = extractOwnerFieldFromMethod(mi.getMethod());

        Authentication auth = authentication.get();
        AuthorizationContext authorizationContext = contextHandler.create(auth, mi);

        CustomMethodSecurityExpressionRoot root = new CustomMethodSecurityExpressionRoot(auth, authorizationContext, auditLogRepository, stringRedisTemplate);
        root.setOwnerField(ownerField);
        root.setApplicationContext(applicationContext);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(getTrustResolver());
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix(getDefaultRolePrefix());
        root.setThis(mi.getThis());

        MethodBasedEvaluationContext ctx = new MethodBasedEvaluationContext(root, mi.getMethod(), mi.getArguments(), getParameterNameDiscoverer());
        ctx.setBeanResolver(getBeanResolver());
        ctx.setVariable("ai", root);

        if (StringUtils.hasText(ownerField)) {
            ctx.setVariable("ownerField", ownerField);
        }

        Method method = mi.getMethod();
        String params = Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName)
                .collect(Collectors.joining(","));
        String methodIdentifier = String.format("%s.%s(%s)", method.getDeclaringClass().getName(), method.getName(), params);

        List<Policy> protectablePolicies = policyRetrievalPoint.findMethodPolicies(methodIdentifier);
        String protectableExpression = buildExpressionFromPoliciesWithDefault(protectablePolicies);
        Expression protectableRule = getExpressionParser().parseExpression(protectableExpression);
        ctx.setVariable("protectableRule", protectableRule);

        auditLogService.logDecision(auth.getName(), methodIdentifier, "METHOD_INVOCATION", "EVALUATING",
                "Evaluating with protectableRule: " + protectableExpression, null);

        return ctx;
    }

    private String extractOwnerFieldFromMethod(Method method) {
        Protectable protectable = method.getAnnotation(Protectable.class);
        if (protectable != null && StringUtils.hasText(protectable.ownerField())) {
            return protectable.ownerField();
        }
        return null;
    }

    private String buildExpressionFromPoliciesWithDefault(List<Policy> policies) {
        if (CollectionUtils.isEmpty(policies)) {
            return "permitAll";
        }
        return buildExpressionFromPolicies(policies);
    }

    private String buildExpressionFromPolicies(List<Policy> policies) {

        Policy policy = policies.getFirst();

        String conditionExpression = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(condition -> "(" + condition.getExpression() + ")")
                .collect(Collectors.joining(" and "));

        if (conditionExpression.isEmpty()) {
            return (policy.getEffect() == Policy.Effect.ALLOW) ? "true" : "false";
        }
        if (policy.getEffect() == Policy.Effect.DENY) {
            return "!(" + conditionExpression + ")";
        }
        return conditionExpression;
    }
}
