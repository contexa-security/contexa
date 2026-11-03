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

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.DelegatorAuthority;
import io.contexa.contexaiam.security.xacml.pep.DelegatorAuthoritySource;
import io.contexa.contexaiam.security.xacml.pep.UserDetailsDelegatorAuthoritySource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.beans.factory.ObjectProvider;
import io.contexa.contexacore.autonomous.service.AuthorizationDenialRecorder;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.ExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandlerFactory;
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
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;

@AutoConfiguration
@EnableConfigurationProperties(PolicyCombiningProperties.class)
public class IamXacmlPepAutoConfiguration {

    @Bean(name = "contexaExpressionAuthorizationManagerResolver")
    @ConditionalOnMissingBean
    public ExpressionAuthorizationManagerResolver expressionAuthorizationManagerResolver(
            List<ExpressionEvaluator> evaluators,
            @Qualifier("contexaCustomWebSecurityExpressionHandler") SecurityExpressionHandler<RequestAuthorizationContext> customWebSecurityExpressionHandler) {
        return new ExpressionAuthorizationManagerResolver(evaluators, customWebSecurityExpressionHandler);
    }

    
    @Bean(name = "contexaPolicyCombiningEvaluator")
    @ConditionalOnMissingBean
    public PolicyCombiningEvaluator policyCombiningEvaluator() {
        return new PolicyCombiningEvaluator();
    }

    @Bean(name = "contexaCustomDynamicAuthorizationManager")
    @ConditionalOnMissingBean
    public CustomDynamicAuthorizationManager customDynamicAuthorizationManager(
            PolicyRetrievalPoint policyRetrievalPoint,
            ExpressionAuthorizationManagerResolver managerResolver,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            ContextHandler contextHandler,
            @Autowired(required = false) AuthorizationMetrics metricsCollector,
            CentralAuditFacade contexaCentralAuditFacade,
            PolicyCombiningEvaluator contexaPolicyCombiningEvaluator,
            PolicyCombiningProperties policyCombiningProperties,
            ObjectProvider<AuthorizationDenialRecorder> authorizationDenialRecorderProvider,
            ObjectProvider<DelegatorAuthority> delegatorAuthority,
            ObjectProvider<SecurityZeroTrustProperties> securityZeroTrustProperties) {
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, managerResolver,
                objectMapper, contextHandler, metricsCollector, contexaCentralAuditFacade,
                contexaPolicyCombiningEvaluator);
        manager.setCombiningAlgorithm(policyCombiningProperties.getCombiningAlgorithm());
        manager.setNoMatchingUrlPolicyDecision(policyCombiningProperties.getNoMatchingUrlPolicyDecision());
        AuthorizationDenialRecorder authorizationDenialRecorder = authorizationDenialRecorderProvider.getIfAvailable();
        if (authorizationDenialRecorder != null) {
            manager.setAuthorizationDenialRecorder(authorizationDenialRecorder);
        }
        // A1-8: enforced unless zero trust runs in SHADOW mode, read per request so a mode change applies at once.
        delegatorAuthority.ifAvailable(authority -> manager.setDelegatorAuthority(authority, () -> {
            SecurityZeroTrustProperties zeroTrust = securityZeroTrustProperties.getIfAvailable();
            return zeroTrust == null || zeroTrust.isEnforcementEnabled();
        }));
        return manager;
    }

    /**
     * A1-8: the authority of the person a delegated agent acts for comes from a {@link DelegatorAuthoritySource} bean,
     * else from the {@code UserDetailsService}; without either, delegators cannot be checked.
     */
    @Bean(name = "contexaDelegatorAuthority")
    @ConditionalOnMissingBean
    public DelegatorAuthority delegatorAuthority(ObjectProvider<DelegatorAuthoritySource> delegatorAuthoritySource,
                                                 ObjectProvider<UserDetailsService> userDetailsService) {
        DelegatorAuthoritySource source = delegatorAuthoritySource.getIfAvailable();
        if (source == null) {
            UserDetailsService people = userDetailsService.getIfUnique();
            source = people != null ? new UserDetailsDelegatorAuthoritySource(people) : null;
        }
        return new DelegatorAuthority(source);
    }

    @Bean(name = "contexaProtectableMethodAuthorizationManager")
    @ConditionalOnMissingBean
    public ProtectableMethodAuthorizationManager protectableMethodAuthorizationManager(
            CustomMethodSecurityExpressionHandlerFactory expressionHandlerFactory,
            PolicyCombiningEvaluator contexaPolicyCombiningEvaluator) {
        return new ProtectableMethodAuthorizationManager(
                expressionHandlerFactory.getHandler(), contexaPolicyCombiningEvaluator);
    }
}

