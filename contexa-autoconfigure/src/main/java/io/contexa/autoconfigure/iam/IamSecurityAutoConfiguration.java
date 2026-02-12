package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

@AutoConfiguration
public class IamSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            CompositePermissionEvaluator compositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogService auditLogService,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRedisRepository actionRedisRepository) {

        return new CustomMethodSecurityExpressionHandler(
                securityZeroTrustProperties,
                compositePermissionEvaluator,
                roleHierarchy,
                policyRetrievalPoint,
                contextHandler,
                auditLogService,
                auditLogRepository,
                actionRedisRepository);
    }
}
