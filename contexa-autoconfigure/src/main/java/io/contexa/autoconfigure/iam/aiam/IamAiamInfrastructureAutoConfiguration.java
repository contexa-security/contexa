package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionLabIntegration;
import io.contexa.contexaiam.aiam.autonomous.orchestrator.AutonomousPolicySynthesizer;
import io.contexa.contexaiam.aiam.labs.synthesis.DynamicThreatResponseSynthesisLab;
import io.contexa.contexaiam.aiam.listener.StompEventListener;
import io.contexa.contexaiam.aiam.operations.IAMSecurityValidator;
import io.contexa.contexaiam.aiam.pipeline.processor.RiskAssessmentPostProcessor;
import io.contexa.contexaiam.aiam.service.StaticAccessOptimizationService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * IAM AI Infrastructure AutoConfiguration
 */
@AutoConfiguration
public class IamAiamInfrastructureAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AutonomousPolicySynthesizer autonomousPolicySynthesizer(
            PolicyProposalManagementService proposalManagementService,
            PolicyEvolutionLabIntegration labIntegration,
            DynamicThreatResponseSynthesisLab dynamicThreatLab,
            StaticAccessOptimizationService staticAccessService,
            ApplicationEventPublisher eventPublisher,
            AILabFactory labFactory) {
        return new AutonomousPolicySynthesizer(
                proposalManagementService, labIntegration, dynamicThreatLab,
                staticAccessService, eventPublisher, labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentPostProcessor riskAssessmentPostProcessor() {
        return new RiskAssessmentPostProcessor();
    }

    @Bean
    @ConditionalOnMissingBean
    public StompEventListener stompEventListener() {
        return new StompEventListener();
    }

    @Bean
    @ConditionalOnMissingBean
    public StompEventListener.StompConnectedEventListener stompConnectedEventListener() {
        return new StompEventListener.StompConnectedEventListener();
    }

    @Bean
    @ConditionalOnMissingBean
    public StompEventListener.StompDisconnectEventListener stompDisconnectEventListener() {
        return new StompEventListener.StompDisconnectEventListener();
    }

    @Bean
    @ConditionalOnMissingBean
    public IAMSecurityValidator iamSecurityValidator(
            RedisTemplate<String, Object> redisTemplate,
            IAMSecurityValidator.SecurityPatternAnalyzer patternAnalyzer,
            IAMSecurityValidator.ComplianceChecker complianceChecker) {
        return new IAMSecurityValidator(redisTemplate, patternAnalyzer, complianceChecker);
    }

    @Bean
    @ConditionalOnMissingBean
    public IAMSecurityValidator.SecurityPatternAnalyzer securityPatternAnalyzer() {
        return new IAMSecurityValidator.SecurityPatternAnalyzer();
    }

    @Bean
    @ConditionalOnMissingBean
    public IAMSecurityValidator.ComplianceChecker complianceChecker(
            RedisTemplate<String, Object> redisTemplate) {
        return new IAMSecurityValidator.ComplianceChecker(redisTemplate);
    }
}
