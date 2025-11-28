package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.repository.DocumentRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomPermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

/**
 * IAM Security AutoConfiguration
 *
 * <p>
 * Spring Security Method Security Expression Handler를 제공합니다.
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>MethodSecurityExpressionHandler - XACML 기반 메서드 보안 표현식 핸들러</li>
 * </ul>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
public class IamSecurityAutoConfiguration {

    /**
     * Method Security Expression Handler
     *
     * <p>
     * XACML 기반 메서드 보안 표현식 처리를 제공합니다.
     * </p>
     *
     * @param customPermissionEvaluator 커스텀 권한 평가자
     * @param roleHierarchy 역할 계층
     * @param policyRetrievalPoint 정책 조회 포인트
     * @param contextHandler 컨텍스트 핸들러
     * @param attributePIP 속성 정보 포인트
     * @param auditLogService 감사 로그 서비스
     * @param aINativeProcessor AI 네이티브 프로세서
     * @param auditLogRepository 감사 로그 레포지토리
     * @param applicationContext 애플리케이션 컨텍스트
     * @param userRepository 사용자 레포지토리
     * @param groupRepository 그룹 레포지토리
     * @param documentRepository 문서 레포지토리
     * @param redisTemplate Trust Score Redis 템플릿
     * @param notificationService 통합 알림 서비스
     * @return MethodSecurityExpressionHandler
     */
    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
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
            @Qualifier("trustScoreRedisTemplate") RedisTemplate<String, Double> redisTemplate,
            StringRedisTemplate stringRedisTemplate,
            @Autowired(required = false) UnifiedNotificationService notificationService) {

        return new CustomMethodSecurityExpressionHandler(
                customPermissionEvaluator,
                roleHierarchy,
                policyRetrievalPoint,
                contextHandler,
                attributePIP,
                auditLogService,
                aINativeProcessor,
                auditLogRepository,
                applicationContext,
                userRepository,
                groupRepository,
                documentRepository,
                redisTemplate,
                stringRedisTemplate,
                notificationService
        );
    }
}
