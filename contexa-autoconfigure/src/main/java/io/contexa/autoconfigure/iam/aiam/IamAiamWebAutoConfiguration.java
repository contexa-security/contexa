package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
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
    public ZeroTrustSseController zeroTrustSseController(
            ZeroTrustSsePublisher zeroTrustSsePublisher) {
        return new ZeroTrustSseController(zeroTrustSsePublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustPageController zeroTrustPageController(StringRedisTemplate stringRedisTemplate) {
        return new ZeroTrustPageController(stringRedisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustUnblockController zeroTrustUnblockController(
            BlockedUserService blockedUserService, StringRedisTemplate stringRedisTemplate) {
        return new ZeroTrustUnblockController(blockedUserService, stringRedisTemplate);
    }
}
