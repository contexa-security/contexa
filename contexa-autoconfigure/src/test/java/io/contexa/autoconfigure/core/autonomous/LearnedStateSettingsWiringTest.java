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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.RedisBaselineDataStore;
import io.contexa.contexacore.autonomous.service.LearningPromotionService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * BR-C11, BR-C14 and QF-28: the stores of the learned state take the host's retention and observation capacity, the
 * defaults leaving them as they were, and the learning promotion runs under the configured lock service.
 */
class LearnedStateSettingsWiringTest {

    @Test
    void theBaselineStoresKeepABaselineForTheConfiguredRetention() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        assertThat(properties.getBaseline().getRetention()).isEqualTo(Duration.ofDays(30));
        properties.getBaseline().setRetention(Duration.ofHours(2));
        @SuppressWarnings("unchecked")
        RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);

        RedisBaselineDataStore redis = new CoreAutonomousAutoConfiguration.DistributedRepositoryConfiguration()
                .baselineDataStore(redisTemplate, properties);
        InMemoryBaselineDataStore memory = new CoreAutonomousAutoConfiguration().baselineDataStore(properties);

        assertThat(ReflectionTestUtils.getField(redis, "baselineTtl")).isEqualTo(Duration.ofHours(2));
        assertThat(memory).isNotNull();
        assertThat(ReflectionTestUtils.getField(new RedisBaselineDataStore(redisTemplate), "baselineTtl"))
                .isEqualTo(Duration.ofDays(30));
    }

    @Test
    void theObservationStoresKeepTheConfiguredCapacity() {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        assertThat(properties.getContext().getObservationCapacity()).isEqualTo(5_000);
        properties.getContext().setObservationCapacity(8_000);
        @SuppressWarnings("unchecked")
        RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);

        InMemorySecurityContextDataStore memory = new CoreAutonomousAutoConfiguration()
                .inMemorySecurityContextDataStore(provider(properties), provider(null));
        RedisSecurityContextDataStore redis = new CoreAutonomousAutoConfiguration.DistributedRepositoryConfiguration()
                .redisSecurityContextDataStore(redisTemplate, provider(properties));

        assertThat(memory.observationCapacity()).isEqualTo(8_000);
        assertThat(redis.observationCapacity()).isEqualTo(8_000);
        assertThat(new InMemorySecurityContextDataStore().observationCapacity()).isEqualTo(5_000);
    }

    @Test
    void theLearningPromotionRunsUnderTheConfiguredLockService() {
        DistributedLockService locks = mock(DistributedLockService.class);

        LearningPromotionService promotion = new CoreAutonomousAutoConfiguration().learningPromotionService(
                mock(SecurityContextDataStore.class), provider(null), provider(null),
                new SecurityZeroTrustProperties(), provider(locks));

        assertThat(ReflectionTestUtils.getField(promotion, "lockService")).isSameAs(locks);
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T bean) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(bean);
        return provider;
    }
}
