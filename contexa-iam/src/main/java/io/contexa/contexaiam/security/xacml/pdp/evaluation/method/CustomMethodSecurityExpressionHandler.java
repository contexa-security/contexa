package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
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

/**
 * [AI 강화] 커스텀 메서드 보안 표현식 핸들러
 * 
 * 기존 기능 완전 보존하면서 AI-Native 위험 평가 기능을 추가한 핸들러입니다.
 * Zero Trust 지원: TrustSecurityExpressionRoot 또는 RealtimeAISecurityExpressionRoot 선택
 */
@Slf4j
public class CustomMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final ContextHandler contextHandler;
    private final DocumentRepository documentRepository;
    private final AttributeInformationPoint attributePIP;
    private final AuditLogService auditLogService;
    
    // === 신규 AI 의존성 ===
    private final AINativeProcessor aINativeProcessor;
    private final AuditLogRepository auditLogRepository;
    private final ApplicationContext applicationContext;
    
    // === Repository 의존성 (ID 기반 소유자 확인용) ===
    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    
    // === Zero Trust 의존성 ===
    private final RedisTemplate<String, Double> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;  // 세션-사용자 매핑 조회용
    private final UnifiedNotificationService notificationService;
    
    // Zero Trust 모드 설정
    @Value("${security.zerotrust.mode:STANDARD}")
    private String zeroTrustMode; // STANDARD, TRUST, REALTIME

    public CustomMethodSecurityExpressionHandler(
            CustomPermissionEvaluator customPermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AttributeInformationPoint attributePIP,
            AuditLogService auditLogService,
            AINativeProcessor aINativeProcessor,
            AuditLogRepository auditLogRepository,
            ApplicationContext applicationContext,
            UserRepository userRepository,
            GroupRepository groupRepository,
            DocumentRepository documentRepository,
            RedisTemplate<String, Double> redisTemplate,
            StringRedisTemplate stringRedisTemplate,
            UnifiedNotificationService notificationService) {
        Assert.notNull(policyRetrievalPoint, "PolicyRetrievalPoint cannot be null");

        this.policyRetrievalPoint = policyRetrievalPoint;
        this.contextHandler = contextHandler;
        this.attributePIP = attributePIP;
        this.auditLogService = auditLogService;
        this.aINativeProcessor = aINativeProcessor;
        this.auditLogRepository = auditLogRepository;
        this.applicationContext = applicationContext;
        this.userRepository = userRepository;
        this.documentRepository = documentRepository;
        this.groupRepository = groupRepository;
        this.redisTemplate = redisTemplate;
        this.stringRedisTemplate = stringRedisTemplate;
        this.notificationService = notificationService;
        super.setPermissionEvaluator(customPermissionEvaluator);
        super.setRoleHierarchy(roleHierarchy);

        log.info("CustomMethodSecurityExpressionHandler 초기화 완료 - Zero Trust 모드: {}", zeroTrustMode);
    }

    @Override
    public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) {

        // 1. @Protectable 애노테이션에서 ownerField 추출 (MethodInvocation 활용)
        String ownerField = extractOwnerFieldFromMethod(mi.getMethod());
        log.debug("🏠 @Protectable ownerField 추출: {}", ownerField);

        // 2. Zero Trust 모드에 따라 적절한 Expression Root 선택
        Authentication auth = authentication.get();
        AuthorizationContext authorizationContext = contextHandler.create(auth, mi);
        
        AbstractAISecurityExpressionRoot root;
        
        // Zero Trust 모드별 Expression Root 생성
        switch (zeroTrustMode) {
            case "TRUST":
                // Hot Path - Redis 조회만 수행
                root = new TrustSecurityExpressionRoot(
                    auth, attributePIP, aINativeProcessor, authorizationContext,
                    auditLogRepository, redisTemplate, stringRedisTemplate, notificationService);
                log.debug("Zero Trust TRUST 모드 - TrustSecurityExpressionRoot 사용 (Redis 조회)");
                break;
                
            case "REALTIME":
                // 실시간 AI 분석 (고위험 작업)
                root = new RealtimeAISecurityExpressionRoot(
                    auth, attributePIP, aINativeProcessor, authorizationContext, 
                    auditLogRepository);
                log.debug("Zero Trust REALTIME 모드 - RealtimeAISecurityExpressionRoot 사용 (실시간 AI)");
                break;
                
            case "STANDARD":
            default:
                // 기존 CustomMethodSecurityExpressionRoot 사용
                CustomMethodSecurityExpressionRoot customRoot = new CustomMethodSecurityExpressionRoot(
                    auth, attributePIP, authorizationContext, aINativeProcessor, auditLogRepository, mi);
                customRoot.setOwnerField(ownerField);
                customRoot.setRepositories(userRepository, groupRepository, documentRepository, applicationContext);
                root = customRoot;
                log.debug("STANDARD 모드 - CustomMethodSecurityExpressionRoot 사용");
                break;
        }

        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(getTrustResolver());
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix(getDefaultRolePrefix());
        if (root instanceof CustomMethodSecurityExpressionRoot) {
            ((CustomMethodSecurityExpressionRoot) root).setThis(mi.getThis());
        }

        // 4. ExpressionRoot를 기반으로 최종 EvaluationContext 생성
        MethodBasedEvaluationContext ctx = new MethodBasedEvaluationContext(root, mi.getMethod(), mi.getArguments(), getParameterNameDiscoverer());
        ctx.setBeanResolver(getBeanResolver());

        // SpEL 변수 설정 - Zero Trust 모드별로 다른 변수 제공
        if (zeroTrustMode.equals("TRUST")) {
            ctx.setVariable("trust", root); // #trust.levelExceeds() 지원
            log.debug("SpEL 변수 설정: #trust → TrustSecurityExpressionRoot 인스턴스");
        } else if (zeroTrustMode.equals("REALTIME")) {
            ctx.setVariable("ai", root); // #ai.analyzeFraud() 지원
            log.debug("SpEL 변수 설정: #ai → RealtimeAISecurityExpressionRoot 인스턴스");
        } else {
            ctx.setVariable("ai", root); // 기존 #ai.assessContext() 지원
            log.debug("SpEL 변수 설정: #ai → CustomMethodSecurityExpressionRoot 인스턴스");
        }
        
        // 🏠 ownerField 정보를 SpEL 변수로도 설정
        if (StringUtils.hasText(ownerField)) {
            ctx.setVariable("ownerField", ownerField);
            log.debug("🏠 SpEL 변수 설정: #ownerField → {}", ownerField);
        }
        
        log.debug("SpEL 변수 설정 완료: #ai → CustomMethodSecurityExpressionRoot 인스턴스");

        // 5. PRP를 통해 동적 규칙(SpEL) 조회
        Method method = mi.getMethod();
        String params = Arrays.stream(method.getParameterTypes())
                .map(Class::getSimpleName)
                .collect(Collectors.joining(","));
        String methodIdentifier = String.format("%s.%s(%s)", method.getDeclaringClass().getName(), method.getName(), params);
        List<Policy> policies = policyRetrievalPoint.findMethodPolicies(methodIdentifier);

        // 6. 조회된 정책을 기반으로 최종 SpEL 표현식 생성 (기본값: denyAll)
        String finalExpression = "denyAll";
        if (!CollectionUtils.isEmpty(policies)) {
            finalExpression = buildExpressionFromPolicies(policies);
        } else {
            log.trace("No dynamic method policy for [{}]. Denying by default.", methodIdentifier);
        }

        // 7. 최종 표현식을 파싱하여 컨텍스트 변수 #dynamicRule 에 할당
        Expression dynamicRuleExpression = getExpressionParser().parseExpression(finalExpression);
        ctx.setVariable("dynamicRule", dynamicRuleExpression);

        log.debug("Dynamic SpEL for method [{}] is: {}", methodIdentifier, finalExpression);

        // 8. 감사 로그 기록
        auditLogService.logDecision(auth.getName(), methodIdentifier, "METHOD_INVOCATION", "EVALUATING", "Evaluating with dynamic rule: " + finalExpression, null);

        return ctx;
    }
    
    /**
     * 🏠 MethodInvocation에서 @Protectable 애노테이션의 ownerField 추출 (Spring Security 표준 방식)
     */
    private String extractOwnerFieldFromMethod(Method method) {
        Protectable protectable = method.getAnnotation(Protectable.class);
        if (protectable != null && StringUtils.hasText(protectable.ownerField())) {
            return protectable.ownerField();
        }
        return null;
    }

    private String buildExpressionFromPolicies(List<Policy> policies) {
        // 가장 우선순위가 높은 정책 하나만 사용.
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