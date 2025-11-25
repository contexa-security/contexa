package io.contexa.autoconfigure.iam.xacml;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.publisher.AuthorizationEventPublisher;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.EventPublishingMetrics;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ExpressionAuthorizationManagerResolver;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.ExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;

/**
 * XACML PEP (Policy Enforcement Point) AutoConfiguration
 */
@AutoConfiguration
public class IamXacmlPepAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ExpressionAuthorizationManagerResolver expressionAuthorizationManagerResolver(
            List<ExpressionEvaluator> evaluators,
            @Qualifier("customWebSecurityExpressionHandler") SecurityExpressionHandler<RequestAuthorizationContext> customWebSecurityExpressionHandler) {
        return new ExpressionAuthorizationManagerResolver(evaluators, customWebSecurityExpressionHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomDynamicAuthorizationManager customDynamicAuthorizationManager(
            PolicyRetrievalPoint policyRetrievalPoint,
            ExpressionAuthorizationManagerResolver managerResolver,
            AuditLogService auditLogService,
            ObjectMapper objectMapper,
            ContextHandler contextHandler,
            AuthorizationEventPublisher authorizationEventPublisher,
            @Autowired(required = false) EventPublishingMetrics metricsCollector) {
        return new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, managerResolver, auditLogService,
                objectMapper, contextHandler, authorizationEventPublisher, metricsCollector);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager(
            @Qualifier("methodSecurityExpressionHandler") MethodSecurityExpressionHandler expressionHandler,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager dynamicAuthorizationManager) {
        return new ProtectableMethodAuthorizationManager(
                expressionHandler, policyRetrievalPoint, dynamicAuthorizationManager);
    }
}
