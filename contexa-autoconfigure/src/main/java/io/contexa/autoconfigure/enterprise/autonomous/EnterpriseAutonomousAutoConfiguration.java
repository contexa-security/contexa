package io.contexa.autoconfigure.enterprise.autonomous;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacoreenterprise.autonomous.controller.PolicyWorkbenchController;
import io.contexa.contexacoreenterprise.autonomous.evolution.AutonomousLearningCoordinator;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyActivationServiceImpl;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionEngine;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.autonomous.monitor.PolicyAuditLogger;
import io.contexa.contexacoreenterprise.autonomous.notification.DefaultNotificationService;
import io.contexa.contexacoreenterprise.autonomous.validation.SpelValidationService;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacoreenterprise.properties.GovernanceProperties;
import io.contexa.contexacoreenterprise.properties.PolicyEvolutionProperties;
import io.contexa.contexacoreenterprise.properties.SecurityAutonomousProperties;
import io.contexa.contexacoreenterprise.properties.SecurityEvaluatorProperties;
import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.autonomous.evolution.PolicyActivationServiceImpl")
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@EnableConfigurationProperties({ ContexaProperties.class, SecurityAutonomousProperties.class,
        SecurityEvaluatorProperties.class, PolicyEvolutionProperties.class, GovernanceProperties.class })
public class EnterpriseAutonomousAutoConfiguration {

    public EnterpriseAutonomousAutoConfiguration() {

    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SynthesisPolicyRepository synthesisPolicyRepository() {
        return new SynthesisPolicyRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyApprovalService policyApprovalService(
            PolicyProposalRepository proposalRepository,
            ApplicationEventPublisher eventPublisher,
            GovernanceProperties governanceProperties,
            @Autowired(required = false) PolicyActivationService policyActivationService) {
        return new PolicyApprovalService(proposalRepository, eventPublisher, governanceProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionEngine policyEvolutionEngine(
            ChatModel chatModel,
            UnifiedVectorService unifiedVectorService,
            PolicyEvolutionProperties policyEvolutionProperties) {
        return new PolicyEvolutionEngine(
                chatModel, unifiedVectorService, policyEvolutionProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionGovernance policyEvolutionGovernance(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            ApplicationEventPublisher eventPublisher,
            GovernanceProperties governanceProperties) {
        return new PolicyEvolutionGovernance(
                proposalRepository, activationService, approvalService, eventPublisher, governanceProperties);
    }

    @Bean
    @ConditionalOnMissingBean(PolicyActivationService.class)
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyActivationService policyActivationService() {
        return new PolicyActivationServiceImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AutonomousLearningCoordinator autonomousLearningCoordinator(
            PolicyEvolutionEngine evolutionEngine,
            PolicyProposalRepository proposalRepository,
            EvolutionMetricsCollector evolutionMetricsCollector,
            SecurityAutonomousProperties securityAutonomousProperties) {
        return new AutonomousLearningCoordinator(evolutionEngine, proposalRepository, evolutionMetricsCollector, securityAutonomousProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyAuditLogger policyAuditLogger(
            SynthesisPolicyRepository synthesisPolicyRepository) {
        return new PolicyAuditLogger(synthesisPolicyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public DefaultNotificationService defaultNotificationService() {
        return new DefaultNotificationService();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyWorkbenchController policyWorkbenchController(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            PolicyEvolutionGovernance governanceService,
            SynthesisPolicyRepository synthesisPolicyRepository,
            PolicyProposalAnalytics analyticsService) {
        return new PolicyWorkbenchController(
                proposalRepository, activationService, approvalService,
                governanceService, synthesisPolicyRepository, analyticsService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ProposalToPolicyConverter proposalToPolicyConverter(
            @Autowired(required = false) SpelValidationService spelValidationService) {
        return new ProposalToPolicyConverter(spelValidationService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnClass(name = "io.contexa.contexaiam.security.xacml.pap.service.PolicyService")
    public PolicyActivationEventListener policyActivationEventListener(
            PolicyProposalRepository proposalRepository,
            ProposalToPolicyConverter proposalToPolicyConverter,
            PolicyService policyService,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager authorizationManager) {
        return new PolicyActivationEventListener(
                proposalRepository,
                proposalToPolicyConverter,
                policyService,
                policyRetrievalPoint,
                authorizationManager);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SpelValidationService spelValidationService() {
        return new SpelValidationService();
    }

}
