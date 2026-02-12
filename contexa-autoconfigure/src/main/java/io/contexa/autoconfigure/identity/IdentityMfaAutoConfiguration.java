package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.MfaPageGeneratingConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.AIAdaptiveMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.DefaultMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.DefaultMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.MfaPolicyEvaluator;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.ZeroTrustPolicyEvaluator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;

@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.mfa", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IdentityMfaAutoConfiguration {

    public IdentityMfaAutoConfiguration() {

    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultMfaPolicyEvaluator defaultMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            ZeroTrustActionRedisRepository actionRedisRepository) {
        return new DefaultMfaPolicyEvaluator(userRepository, applicationContext, actionRedisRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustPolicyEvaluator zeroTrustPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            ZeroTrustActionRedisRepository actionRedisRepository,
            HcadProperties hcadProperties) {
        return new ZeroTrustPolicyEvaluator(
                userRepository, applicationContext, actionRedisRepository, hcadProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CompositeMfaPolicyEvaluator compositeMfaPolicyEvaluator(
            List<MfaPolicyEvaluator> evaluators) {
        return new CompositeMfaPolicyEvaluator(evaluators);
    }

    @Bean
    @ConditionalOnMissingBean(name = "defaultMfaPolicyProvider")
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

    @Bean
    @Primary
    @ConditionalOnBean(AICoreOperations.class)
    @ConditionalOnMissingBean(name = "aiAdaptiveMfaPolicyProvider")
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

    @Bean
    @ConditionalOnMissingBean
    public MfaPageGeneratingConfigurer mfaPageGeneratingConfigurer(ApplicationContext applicationContext) {
        return new MfaPageGeneratingConfigurer(applicationContext);
    }
}
