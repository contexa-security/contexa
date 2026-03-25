package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.autonomous.store.InMemoryBlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.RedisBlockMfaStateStore;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;


@AutoConfiguration
@EnableConfigurationProperties(SecurityStepUpProperties.class)
public class IamAiamWebAutoConfiguration {

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
    public ZeroTrustPageController zeroTrustPageController(BlockMfaStateStore blockMfaStateStore,
                                                            BlockedUserJpaRepository blockedUserJpaRepository,
                                                            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustPageController(blockMfaStateStore, blockedUserJpaRepository, securityZeroTrustProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustUnblockController zeroTrustUnblockController(
            BlockedUserService blockedUserService, BlockMfaStateStore blockMfaStateStore,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustUnblockController(blockedUserService, blockMfaStateStore, securityZeroTrustProperties);
    }

    @Configuration
    @ConditionalOnBean(StringRedisTemplate.class)
    static class DistributedBlockMfaConfig {

        @Bean
        @ConditionalOnMissingBean(BlockMfaStateStore.class)
        public RedisBlockMfaStateStore redisBlockMfaStateStore(StringRedisTemplate stringRedisTemplate) {
            return new RedisBlockMfaStateStore(stringRedisTemplate);
        }
    }

    @Configuration
    @ConditionalOnMissingBean(StringRedisTemplate.class)
    static class StandaloneBlockMfaConfig {

        @Bean
        @ConditionalOnMissingBean(BlockMfaStateStore.class)
        public InMemoryBlockMfaStateStore inMemoryBlockMfaStateStore(
                ZeroTrustActionRepository actionRepository) {
            return new InMemoryBlockMfaStateStore(actionRepository);
        }
    }
}
