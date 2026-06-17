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
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Activates Spring Security's method-level authorization machinery so {@code @PreAuthorize},
 * {@code @PostAuthorize}, {@code @Secured}, and JSR-250 annotations on any IAM controller or
 * service are intercepted. Without this annotation the configured
 * {@link MethodSecurityExpressionHandler} bean is never wired to a method interceptor and
 * the annotations on every controller are silently ignored — including the defence-in-depth
 * guards on the system-settings endpoints.
 */
@AutoConfiguration
@EnableMethodSecurity
@EnableConfigurationProperties(PolicyCombiningProperties.class)
@AutoConfigureAfter(name = {
        "io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration",
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
public class IamSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            CompositePermissionEvaluator compositePermissionEvaluator,
            RoleHierarchy roleHierarchy,
            PolicyRetrievalPoint policyRetrievalPoint,
            ContextHandler contextHandler,
            AuditLogRepository auditLogRepository,
            ZeroTrustActionRepository actionRedisRepository,
            PolicyCombiningProperties policyCombiningProperties) {

        return new CustomMethodSecurityExpressionHandler(
                securityZeroTrustProperties,
                compositePermissionEvaluator,
                roleHierarchy,
                policyRetrievalPoint,
                contextHandler,
                auditLogRepository,
                actionRedisRepository,
                policyCombiningProperties.getMissingMethodPolicyDecision());
    }
}

