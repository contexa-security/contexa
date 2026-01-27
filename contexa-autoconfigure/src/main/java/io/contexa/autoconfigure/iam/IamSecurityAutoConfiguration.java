package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.repository.DocumentRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomPermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

@AutoConfiguration
public class IamSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            @Value("${security.zerotrust.mode:TRUST}") String zeroTrustMode,
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
            StringRedisTemplate stringRedisTemplate) {

        return new CustomMethodSecurityExpressionHandler(
                zeroTrustMode,
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
                stringRedisTemplate);
    }
}
