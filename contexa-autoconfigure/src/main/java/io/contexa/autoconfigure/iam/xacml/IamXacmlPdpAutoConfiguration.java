/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

import java.util.List;


@AutoConfiguration
public class IamXacmlPdpAutoConfiguration {

    
    @Bean(name = "contexaRoleFunctionTranslator")
    @ConditionalOnMissingBean
    public RoleFunctionTranslator roleFunctionTranslator() {
        return new RoleFunctionTranslator();
    }

    @Bean(name = "contexaAuthenticationFunctionTranslator")
    @ConditionalOnMissingBean
    public AuthenticationFunctionTranslator authenticationFunctionTranslator() {
        return new AuthenticationFunctionTranslator();
    }

    @Bean(name = "contexaAuthorityFunctionTranslator")
    @ConditionalOnMissingBean
    public AuthorityFunctionTranslator authorityFunctionTranslator() {
        return new AuthorityFunctionTranslator();
    }

    @Bean(name = "contexaIpAddressFunctionTranslator")
    @ConditionalOnMissingBean
    public IpAddressFunctionTranslator ipAddressFunctionTranslator() {
        return new IpAddressFunctionTranslator();
    }

    @Bean(name = "contexaDefaultFunctionTranslator")
    @ConditionalOnMissingBean
    public DefaultFunctionTranslator defaultFunctionTranslator() {
        return new DefaultFunctionTranslator();
    }

    @Bean(name = "contexaPolicyTranslator")
    @ConditionalOnMissingBean
    public PolicyTranslator policyTranslator(
            RoleRepository roleRepository,
            GroupRepository groupRepository,
            PermissionRepository permissionRepository,
            List<SpelFunctionTranslator> translators) {
        return new PolicyTranslator(roleRepository, groupRepository, permissionRepository, translators);
    }

    
    @Bean(name = "contexaWebSpelExpressionEvaluator")
    @ConditionalOnMissingBean
    public WebSpelExpressionEvaluator webSpelExpressionEvaluator() {
        return new WebSpelExpressionEvaluator();
    }

    @Bean(name = "contexaAuthenticatedExpressionEvaluator")
    @ConditionalOnMissingBean
    public AuthenticatedExpressionEvaluator authenticatedExpressionEvaluator() {
        return new AuthenticatedExpressionEvaluator();
    }

    @Bean(name = "contexaAuthorityExpressionEvaluator")
    @ConditionalOnMissingBean
    public AuthorityExpressionEvaluator authorityExpressionEvaluator() {
        return new AuthorityExpressionEvaluator();
    }

    @Bean(name = "contexaCustomWebSecurityExpressionHandler")
    @ConditionalOnMissingBean
    public CustomWebSecurityExpressionHandler customWebSecurityExpressionHandler(
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository,
            RoleHierarchy roleHierarchy) {
        return new CustomWebSecurityExpressionHandler(contextHandler, auditLogRepository, actionRedisRepository, roleHierarchy);
    }


    @Bean(name = "contexaGroupPermissionEvaluator")
    @ConditionalOnMissingBean
    public GroupPermissionEvaluator groupPermissionEvaluator(ApplicationContext ctx) {
        return new GroupPermissionEvaluator(ctx);
    }

    @Bean(name = "contexaUserPermissionEvaluator")
    @ConditionalOnMissingBean
    public UserPermissionEvaluator userPermissionEvaluator(ApplicationContext ctx) {
        return new UserPermissionEvaluator(ctx);
    }

    @Bean(name = "contexaPermissionTargetPermissionEvaluator")
    @ConditionalOnMissingBean
    public PermissionTargetPermissionEvaluator permissionTargetPermissionEvaluator(ApplicationContext ctx) {
        return new PermissionTargetPermissionEvaluator(ctx);
    }

    @Bean(name = "contexaRolePermissionEvaluator")
    @ConditionalOnMissingBean
    public RolePermissionEvaluator rolePermissionEvaluator(ApplicationContext ctx) {
        return new RolePermissionEvaluator(ctx);
    }

    @Bean(name = "contexaRoleHierarchyPermissionEvaluator")
    @ConditionalOnMissingBean
    public RoleHierarchyPermissionEvaluator roleHierarchyPermissionEvaluator(ApplicationContext ctx) {
        return new RoleHierarchyPermissionEvaluator(ctx);
    }

    @Bean(name = "contexaCompositePermissionEvaluator")
    @ConditionalOnMissingBean
    public CompositePermissionEvaluator compositePermissionEvaluator(
            List<DomainPermissionEvaluator> evaluators) {
        return new CompositePermissionEvaluator(evaluators);
    }
}

