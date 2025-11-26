package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.service.SecurityCopilotMessageProvider;
import io.contexa.contexaiam.aiam.service.SecurityCopilotValidationService;
import io.contexa.contexaiam.aiam.service.SoarActionService;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
import io.contexa.contexaiam.service.PolicyService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * IAM AIAM Web Controllers AutoConfiguration
 */
@AutoConfiguration
@EnableConfigurationProperties(SecurityStepUpProperties.class)
public class IamAiamWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotController securityCopilotController(
            AICoreOperations<SecurityCopilotContext> aiNativeProcessor,
            SecurityCopilotValidationService validationService,
            SecurityCopilotMessageProvider messageProvider) {
        return new SecurityCopilotController(aiNativeProcessor, validationService, messageProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneController securityPlaneController() {
        return new SecurityPlaneController();
    }


    @Bean
    @ConditionalOnMissingBean
    public WebSocketTestMessageController webSocketTestMessageController(
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new WebSocketTestMessageController(brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public StepUpAuthController stepUpAuthController(
            RedisTemplate<String, Object> redisTemplate,
            PasswordEncoder passwordEncoder,
            UserDetailsService userDetailsService) {
        return new StepUpAuthController(redisTemplate, passwordEncoder, userDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(SoarActionService.class)
    public SoarActionController soarActionController(SoarActionService soarActionService) {
        return new SoarActionController(soarActionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AIPolicyApprovalViewController aiPolicyApprovalViewController() {
        return new AIPolicyApprovalViewController();
    }

    @Bean
    @ConditionalOnMissingBean
    public AIPolicyApprovalController aiPolicyApprovalController(PolicyService policyService) {
        return new AIPolicyApprovalController(policyService);
    }
}
