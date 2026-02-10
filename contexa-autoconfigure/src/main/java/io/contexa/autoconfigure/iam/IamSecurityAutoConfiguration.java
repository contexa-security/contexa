package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

@AutoConfiguration
public class IamSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            @Value("${security.zerotrust.mode:TRUST}") String zeroTrustMode,
            CompositePermissionEvaluator compositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogService auditLogService,
            AuditLogRepository auditLogRepository,
            ApplicationContext applicationContext,
            StringRedisTemplate stringRedisTemplate) {

        return new CustomMethodSecurityExpressionHandler(
                zeroTrustMode,
                compositePermissionEvaluator,
                roleHierarchy,
                policyRetrievalPoint,
                contextHandler,
                auditLogService,
                auditLogRepository,
                applicationContext,
                stringRedisTemplate);
    }
}
