package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionLabIntegration;
import io.contexa.contexaiam.aiam.listener.StompEventListener;
import io.contexa.contexaiam.aiam.pipeline.processor.RiskAssessmentPostProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;


@AutoConfiguration
public class IamAiamInfrastructureAutoConfiguration {

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
}
