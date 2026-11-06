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

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.RedisStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * The store of what a step-up hands out and of the claims on what may happen only once in a while, in memory or in Redis
 * in a distributed deployment. It stands under either ownership: the step-up of an application that owns its sign-in
 * keeps its options there, and the mail of a one-time code is claimed there when Contexa owns sign-in too.
 */
@AutoConfiguration
@AutoConfigureAfter(IdentitySecurityCoreAutoConfiguration.class)
@ConditionalOnBean(PlatformConfig.class)
public class StepUpOptionsStoreAutoConfiguration {

    /** A distributed deployment shares the store, so an answer may reach another instance and a claim holds on all of them. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.data.redis.core.StringRedisTemplate")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    static class DistributedStepUpOptions {

        @Bean(name = "contexaStepUpOptionsStore")
        @ConditionalOnMissingBean(StepUpOptionsStore.class)
        @ConditionalOnBean(StringRedisTemplate.class)
        public StepUpOptionsStore stepUpOptionsStore(StringRedisTemplate redis,
                @Qualifier("contexaStringRedisTemplate") ObjectProvider<StringRedisTemplate> contexaStrings) {
            return new RedisStepUpOptionsStore(contexaStrings.getIfAvailable(() -> redis));
        }
    }

    @Bean(name = "contexaInMemoryStepUpOptionsStore")
    @ConditionalOnMissingBean(StepUpOptionsStore.class)
    public InMemoryStepUpOptionsStore inMemoryStepUpOptionsStore() {
        return new InMemoryStepUpOptionsStore();
    }
}
