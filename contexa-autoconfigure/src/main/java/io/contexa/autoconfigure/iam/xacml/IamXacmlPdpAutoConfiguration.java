package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.*;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthenticatedExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthorityExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.CustomWebSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.translator.*;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

import java.util.List;


@AutoConfiguration
public class IamXacmlPdpAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public RoleFunctionTranslator roleFunctionTranslator() {
        return new RoleFunctionTranslator();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationFunctionTranslator authenticationFunctionTranslator() {
        return new AuthenticationFunctionTranslator();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorityFunctionTranslator authorityFunctionTranslator() {
        return new AuthorityFunctionTranslator();
    }

    @Bean
    @ConditionalOnMissingBean
    public IpAddressFunctionTranslator ipAddressFunctionTranslator() {
        return new IpAddressFunctionTranslator();
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultFunctionTranslator defaultFunctionTranslator() {
        return new DefaultFunctionTranslator();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyTranslator policyTranslator(
            RoleRepository roleRepository,
            GroupRepository groupRepository,
            PermissionRepository permissionRepository,
            List<SpelFunctionTranslator> translators) {
        return new PolicyTranslator(roleRepository, groupRepository, permissionRepository, translators);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public WebSpelExpressionEvaluator webSpelExpressionEvaluator() {
        return new WebSpelExpressionEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticatedExpressionEvaluator authenticatedExpressionEvaluator() {
        return new AuthenticatedExpressionEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorityExpressionEvaluator authorityExpressionEvaluator() {
        return new AuthorityExpressionEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomWebSecurityExpressionHandler customWebSecurityExpressionHandler(
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository,
            RoleHierarchy roleHierarchy) {
        return new CustomWebSecurityExpressionHandler(contextHandler, auditLogRepository, actionRedisRepository, roleHierarchy);
    }


    @Bean
    @ConditionalOnMissingBean
    public GroupPermissionEvaluator groupPermissionEvaluator(ApplicationContext ctx) {
        return new GroupPermissionEvaluator(ctx);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserPermissionEvaluator userPermissionEvaluator(ApplicationContext ctx) {
        return new UserPermissionEvaluator(ctx);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionTargetPermissionEvaluator permissionTargetPermissionEvaluator(ApplicationContext ctx) {
        return new PermissionTargetPermissionEvaluator(ctx);
    }

    @Bean
    @ConditionalOnMissingBean
    public RolePermissionEvaluator rolePermissionEvaluator(ApplicationContext ctx) {
        return new RolePermissionEvaluator(ctx);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchyPermissionEvaluator roleHierarchyPermissionEvaluator(ApplicationContext ctx) {
        return new RoleHierarchyPermissionEvaluator(ctx);
    }

    @Bean
    @ConditionalOnMissingBean
    public CompositePermissionEvaluator compositePermissionEvaluator(
            List<DomainPermissionEvaluator> evaluators) {
        return new CompositePermissionEvaluator(evaluators);
    }
}
