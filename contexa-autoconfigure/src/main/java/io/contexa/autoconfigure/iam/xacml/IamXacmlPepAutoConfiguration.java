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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.ExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ExpressionAuthorizationManagerResolver;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;

@AutoConfiguration
@EnableConfigurationProperties(PolicyCombiningProperties.class)
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
    public PolicyCombiningEvaluator policyCombiningEvaluator() {
        return new PolicyCombiningEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomDynamicAuthorizationManager customDynamicAuthorizationManager(
            PolicyRetrievalPoint policyRetrievalPoint,
            ExpressionAuthorizationManagerResolver managerResolver,
            ObjectMapper objectMapper,
            ContextHandler contextHandler,
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            @Autowired(required = false) AuthorizationMetrics metricsCollector,
            CentralAuditFacade centralAuditFacade,
            PolicyCombiningEvaluator policyCombiningEvaluator,
            PolicyCombiningProperties policyCombiningProperties) {
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, managerResolver,
                objectMapper, contextHandler, zeroTrustEventPublisher, metricsCollector, centralAuditFacade,
                policyCombiningEvaluator);
        manager.setCombiningAlgorithm(policyCombiningProperties.getCombiningAlgorithm());
        return manager;
    }

    @Bean
    @ConditionalOnMissingBean
    public ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager(
            @Qualifier("methodSecurityExpressionHandler") MethodSecurityExpressionHandler expressionHandler) {
        return new ProtectableMethodAuthorizationManager(expressionHandler);
    }
}

