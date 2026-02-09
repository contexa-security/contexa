package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.DocumentRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.data.redis.core.RedisTemplate;
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
    private final DocumentRepository documentRepository;
    private final AttributeInformationPoint attributePIP;
    private final AuditLogService auditLogService;

    private final AICoreOperations aiNativeProcessor;
    private final AuditLogRepository auditLogRepository;
    private final ApplicationContext applicationContext;

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;

    private final RedisTemplate<String, Double> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;

    private final String zeroTrustMode;

    public CustomMethodSecurityExpressionHandler(
            @Value("${security.zerotrust.mode:TRUST}") String zeroTrustMode,
            CustomPermissionEvaluator customPermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AttributeInformationPoint attributePIP,
            AuditLogService auditLogService,
            AICoreOperations aiNativeProcessor,
            AuditLogRepository auditLogRepository,
            ApplicationContext applicationContext,
            UserRepository userRepository,
            GroupRepository groupRepository,
            DocumentRepository documentRepository,
            RedisTemplate<String, Double> redisTemplate,
            StringRedisTemplate stringRedisTemplate) {
        Assert.notNull(policyRetrievalPoint, "PolicyRetrievalPoint cannot be null");
        Assert.notNull(zeroTrustMode, "zeroTrustMode cannot be null");

        this.zeroTrustMode = zeroTrustMode;
        this.policyRetrievalPoint = policyRetrievalPoint;
        this.contextHandler = contextHandler;
        this.attributePIP = attributePIP;
        this.auditLogService = auditLogService;
        this.aiNativeProcessor = aiNativeProcessor;
        this.auditLogRepository = auditLogRepository;
        this.applicationContext = applicationContext;
        this.userRepository = userRepository;
        this.documentRepository = documentRepository;
        this.groupRepository = groupRepository;
        this.redisTemplate = redisTemplate;
        this.stringRedisTemplate = stringRedisTemplate;
        super.setPermissionEvaluator(customPermissionEvaluator);
        super.setRoleHierarchy(roleHierarchy);

    }

    @Override
    public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) {

        String ownerField = extractOwnerFieldFromMethod(mi.getMethod());

        Authentication auth = authentication.get();
        AuthorizationContext authorizationContext = contextHandler.create(auth, mi);

        AbstractAISecurityExpressionRoot root;

        switch (zeroTrustMode) {
            case "TRUST":

                root = new TrustSecurityExpressionRoot(
                        auth, attributePIP, aiNativeProcessor, authorizationContext,
                        auditLogRepository, stringRedisTemplate);
                break;

            case "STANDARD":
            default:

                CustomMethodSecurityExpressionRoot customRoot = new CustomMethodSecurityExpressionRoot(
                        auth, attributePIP, authorizationContext, aiNativeProcessor, auditLogRepository, mi);
                customRoot.setOwnerField(ownerField);
                customRoot.setRepositories(userRepository, groupRepository, documentRepository, applicationContext);
                root = customRoot;
                break;
        }

        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(getTrustResolver());
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix(getDefaultRolePrefix());
        if (root instanceof CustomMethodSecurityExpressionRoot) {
            ((CustomMethodSecurityExpressionRoot) root).setThis(mi.getThis());
        }

        MethodBasedEvaluationContext ctx = new MethodBasedEvaluationContext(root, mi.getMethod(), mi.getArguments(), getParameterNameDiscoverer());
        ctx.setBeanResolver(getBeanResolver());

        ctx.setVariable("ai", root);
        ctx.setVariable("trust", root);

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