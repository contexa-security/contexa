package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;


@AutoConfiguration
@EnableConfigurationProperties(SecurityStepUpProperties.class)
public class IamAiamWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AiStudioController aiStudioController(
            AICoreOperations<StudioQueryContext> aiNativeProcessor,
            StandardStreamingService streamingService) {
        return new AiStudioController(aiNativeProcessor, streamingService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AiApiController aiApiController(
            AICoreOperations<PolicyContext> aiNativeProcessor,
            StandardStreamingService streamingService) {
        return new AiApiController(aiNativeProcessor, streamingService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideController adminOverrideController(
            AdminOverrideService adminOverrideService,
            StringRedisTemplate stringRedisTemplate) {
        return new AdminOverrideController(adminOverrideService, stringRedisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustSseController zeroTrustSseController(
            ZeroTrustSsePublisher zeroTrustSsePublisher) {
        return new ZeroTrustSseController(zeroTrustSsePublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustPageController zeroTrustPageController() {
        return new ZeroTrustPageController();
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustUnblockController zeroTrustUnblockController(
            AdminOverrideService adminOverrideService,
            StringRedisTemplate stringRedisTemplate) {
        return new ZeroTrustUnblockController(adminOverrideService, stringRedisTemplate);
    }
}
