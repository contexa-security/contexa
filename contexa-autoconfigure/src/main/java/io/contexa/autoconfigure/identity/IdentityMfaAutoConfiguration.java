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
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.MfaPageGeneratingConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.AIAdaptiveMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.DefaultMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.AgentAccountMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.DefaultMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.ZeroTrustPolicyEvaluator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;

@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.mfa", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IdentityMfaAutoConfiguration {

    public IdentityMfaAutoConfiguration() {

    }

    @Bean(name = "contexaDefaultMfaPolicyEvaluator")
    @ConditionalOnMissingBean
    public DefaultMfaPolicyEvaluator defaultMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            ZeroTrustActionRepository actionRedisRepository) {
        return new DefaultMfaPolicyEvaluator(userRepository, applicationContext, actionRedisRepository);
    }

    @Bean(name = "contexaZeroTrustPolicyEvaluator")
    @ConditionalOnMissingBean
    public ZeroTrustPolicyEvaluator zeroTrustPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            ZeroTrustActionRepository actionRedisRepository,
            SecurityZeroTrustProperties zeroTrustProperties) {
        return new ZeroTrustPolicyEvaluator(
                userRepository, applicationContext, actionRedisRepository, zeroTrustProperties);
    }

    /** A1-13: an approved agent's own account signs in by Contexa's zero trust action alone, never with factors. */
    @Bean(name = "contexaAgentAccountMfaPolicyEvaluator")
    @ConditionalOnMissingBean
    public AgentAccountMfaPolicyEvaluator agentAccountMfaPolicyEvaluator(
            ZeroTrustActionRepository actionRedisRepository,
            ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        return new AgentAccountMfaPolicyEvaluator(actionRedisRepository, agentClientDirectory);
    }

    @Bean(name = "contexaCompositeMfaPolicyEvaluator")
    @ConditionalOnMissingBean
    public CompositeMfaPolicyEvaluator compositeMfaPolicyEvaluator(
            List<MfaPolicyEvaluator> evaluators) {
        return new CompositeMfaPolicyEvaluator(evaluators);
    }

    @Bean(name = "contexaDefaultMfaPolicyProvider")
    @ConditionalOnMissingBean(name = "contexaDefaultMfaPolicyProvider")
    public DefaultMfaPolicyProvider defaultMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            CompositeMfaPolicyEvaluator policyEvaluator,
            PlatformConfig platformConfig) {
        return new DefaultMfaPolicyProvider(
                userRepository,
                applicationContext,
                properties,
                policyEvaluator,
                platformConfig);
    }

    @Bean(name = "contexaAiAdaptiveMfaPolicyProvider")
    @Primary
    @ConditionalOnMissingBean(name = "contexaAiAdaptiveMfaPolicyProvider")
    public AIAdaptiveMfaPolicyProvider aiAdaptiveMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            CompositeMfaPolicyEvaluator compositePolicyEvaluator,
            PlatformConfig platformConfig,
            AICoreOperations aiCoreOperations) {
        return new AIAdaptiveMfaPolicyProvider(
                userRepository,
                applicationContext,
                properties,
                compositePolicyEvaluator,
                platformConfig,
                aiCoreOperations);
    }

    @Bean(name = "contexaMfaPageGeneratingConfigurer")
    @ConditionalOnMissingBean
    public MfaPageGeneratingConfigurer mfaPageGeneratingConfigurer(ApplicationContext applicationContext) {
        return new MfaPageGeneratingConfigurer(applicationContext);
    }
}
