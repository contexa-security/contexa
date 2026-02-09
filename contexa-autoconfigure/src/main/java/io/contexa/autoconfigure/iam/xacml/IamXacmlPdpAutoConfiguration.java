package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomPermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthenticatedExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthorityExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.CustomWebSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.translator.AuthenticationFunctionTranslator;
import io.contexa.contexaiam.security.xacml.pdp.translator.AuthorityFunctionTranslator;
import io.contexa.contexaiam.security.xacml.pdp.translator.DefaultFunctionTranslator;
import io.contexa.contexaiam.security.xacml.pdp.translator.IpAddressFunctionTranslator;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexaiam.security.xacml.pdp.translator.RoleFunctionTranslator;
import io.contexa.contexaiam.security.xacml.pdp.translator.SpelFunctionTranslator;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

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
            AuditLogRepository auditLogRepository) {
        return new CustomWebSecurityExpressionHandler(
                contextHandler, auditLogRepository);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public CustomPermissionEvaluator customPermissionEvaluator(
            UserRepository userRepository,
            GroupRepository groupRepository,
            ApplicationContext applicationContext) {
        return new CustomPermissionEvaluator(userRepository, groupRepository, applicationContext);
    }
}
