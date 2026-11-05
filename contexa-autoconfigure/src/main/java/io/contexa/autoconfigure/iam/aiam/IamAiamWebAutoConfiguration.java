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
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;


@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
@EnableConfigurationProperties(SecurityStepUpProperties.class)
public class IamAiamWebAutoConfiguration {

    @Bean(name = "contexaAiApiController")
    @ConditionalOnMissingBean
    public AiApiController aiApiController(
            AICoreOperations<PolicyContext> contexaAiNativeProcessor,
            StandardStreamingService streamingService) {
        return new AiApiController(contexaAiNativeProcessor, streamingService);
    }

    @Bean(name = "contexaZeroTrustSseController")
    @ConditionalOnMissingBean
    public ZeroTrustSseController zeroTrustSseController(
            ZeroTrustSsePublisher contexaZeroTrustSsePublisher) {
        return new ZeroTrustSseController(contexaZeroTrustSsePublisher);
    }

    @Bean(name = "contexaZeroTrustPageController")
    @ConditionalOnMissingBean
    public ZeroTrustPageController zeroTrustPageController(BlockMfaStateStore blockMfaStateStore,
                                                            BlockedUserService contexaBlockedUserService,
                                                            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustPageController(blockMfaStateStore, contexaBlockedUserService, securityZeroTrustProperties);
    }

    @Bean(name = "contexaZeroTrustUnblockController")
    @ConditionalOnMissingBean
    public ZeroTrustUnblockController zeroTrustUnblockController(
            BlockedUserService contexaBlockedUserService, BlockMfaStateStore blockMfaStateStore,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustUnblockController(contexaBlockedUserService, blockMfaStateStore, securityZeroTrustProperties);
    }

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(type = "org.springframework.data.redis.core.StringRedisTemplate")
    static class DistributedBlockMfaConfig {

        @Bean(name = "contexaRedisBlockMfaStateStore")
        @ConditionalOnMissingBean(BlockMfaStateStore.class)
        public RedisBlockMfaStateStore redisBlockMfaStateStore(StringRedisTemplate stringRedisTemplate,
                                                               @Qualifier("contexaStringRedisTemplate") ObjectProvider<StringRedisTemplate> contexaStrings,
                                                               ZeroTrustActionRepository actionRepository) {
            return new RedisBlockMfaStateStore(contexaStrings.getIfAvailable(() -> stringRedisTemplate), actionRepository);
        }
    }

    @Configuration
    static class StandaloneBlockMfaConfig {

        @Bean(name = "contexaInMemoryBlockMfaStateStore")
        @ConditionalOnMissingBean(BlockMfaStateStore.class)
        public InMemoryBlockMfaStateStore inMemoryBlockMfaStateStore(
                ZeroTrustActionRepository actionRepository) {
            return new InMemoryBlockMfaStateStore(actionRepository);
        }
    }
}

