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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandlerFactory;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

/**
 * Provides Contexa's method-policy expression handler without publishing it as host
 * Spring Security infrastructure. When Contexa owns authentication, {@code @PreAuthorize}
 * is applied to Contexa's own classes only.
 */
@AutoConfiguration
@EnableConfigurationProperties(PolicyCombiningProperties.class)
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration",
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
public class IamSecurityAutoConfiguration {

    @Bean(name = "contexaCustomMethodSecurityExpressionHandlerFactory")
    @ConditionalOnMissingBean
    public CustomMethodSecurityExpressionHandlerFactory customMethodSecurityExpressionHandlerFactory(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            CompositePermissionEvaluator contexaCompositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository,
            PolicyCombiningProperties policyCombiningProperties) {

        return new CustomMethodSecurityExpressionHandlerFactory(
                securityZeroTrustProperties,
                contexaCompositePermissionEvaluator,
                roleHierarchy,
                policyRetrievalPoint,
                contextHandler,
                auditLogRepository,
                actionRedisRepository,
                policyCombiningProperties);
    }

    /**
     * {@code @PreAuthorize} for Contexa's own classes, with Contexa's handler. The application's own annotations are not touched, and
     * when the application turned method security on itself, its interceptor (and its handler) already serves Contexa's classes.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(
            prefix = "contexa.bridge",
            name = "ownership",
            havingValue = "CONTEXA_OWNED")
    static class ContexaOwnedMethodSecurityConfiguration {

        @Bean(name = "contexaPreAuthorizeAdvisor")
        @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
        static Advisor contexaPreAuthorizeAdvisor(
                ObjectProvider<CustomMethodSecurityExpressionHandlerFactory> factory,
                ApplicationContext applicationContext) {
            return ContexaScopedMethodSecurity.preAuthorizeAdvisor(() -> factory.getObject().getHandler(), applicationContext);
        }
    }
}

