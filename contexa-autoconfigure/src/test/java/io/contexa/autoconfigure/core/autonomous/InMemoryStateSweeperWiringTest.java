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

import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.autonomous.store.InMemoryStateSweeper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the sweeper of the in-memory stores is declared whatever the infrastructure mode, runs every minute, and
 * reaches the standalone decision and context stores, which are the default ones, through their bean types. Z-16 (B-1,
 * B-2): the baselines, the asynchronous authentications, the locks and the rapid re-entry windows join it the same way.
 */
class InMemoryStateSweeperWiringTest {

    @Test
    void theSweeperRunsEveryMinuteOverTheStandaloneStores() {
        assertThat(beanMethod("inMemoryStateSweeper").getAnnotation(ConditionalOnProperty.class)).isNull();
        assertThat(InMemoryStateSweeper.DEFAULT_INTERVAL).isEqualTo(Duration.ofMinutes(1));
        for (String store : new String[]{"inMemoryZeroTrustActionRepository", "inMemorySecurityContextDataStore"}) {
            ConditionalOnProperty condition = beanMethod(store).getAnnotation(ConditionalOnProperty.class);
            assertThat(condition.name()).containsExactly("contexa.infrastructure.mode");
            assertThat(condition.havingValue()).isEqualTo("standalone");
            assertThat(condition.matchIfMissing()).isTrue();
        }

        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerBeanDefinition("configuration", new RootBeanDefinition(CoreAutonomousAutoConfiguration.class));
        register(beanFactory, "inMemoryZeroTrustActionRepository");
        register(beanFactory, "inMemorySecurityContextDataStore");
        register(beanFactory, "inMemoryStateSweeper");
        AtomicInteger sweeps = new AtomicInteger();
        beanFactory.registerSingleton("countingStore", (ExpiringStateStore) sweeps::incrementAndGet);

        assertThat(beanFactory.getBeanNamesForType(ExpiringStateStore.class))
                .contains("inMemoryZeroTrustActionRepository", "inMemorySecurityContextDataStore", "countingStore");
        InMemoryStateSweeper sweeper = beanFactory.getBean(InMemoryStateSweeper.class);
        try {
            sweeper.sweep();
            assertThat(sweeps).hasValue(1);
        } finally {
            sweeper.close();
        }
    }

    @Test
    void theSweeperAlsoReachesTheStandaloneBaselineAsyncLockAndReentryStores() {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerBeanDefinition("configuration", new RootBeanDefinition(CoreAutonomousAutoConfiguration.class));
        beanFactory.registerSingleton("securityZeroTrustProperties", new SecurityZeroTrustProperties());
        register(beanFactory, "baselineDataStore");
        register(beanFactory, "inMemoryDistributedLockService");
        register(beanFactory, "inMemoryProtectableRapidReentryRepository");
        RootBeanDefinition asyncConfiguration = new RootBeanDefinition();
        asyncConfiguration.setBeanClassName(
                "io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration$StandaloneAsyncConfiguration");
        beanFactory.registerBeanDefinition("asyncConfiguration", asyncConfiguration);
        RootBeanDefinition asyncProvider = new RootBeanDefinition();
        asyncProvider.setFactoryBeanName("asyncConfiguration");
        asyncProvider.setFactoryMethodName("inMemoryAsyncSecurityContextProvider");
        beanFactory.registerBeanDefinition("inMemoryAsyncSecurityContextProvider", asyncProvider);
        register(beanFactory, "inMemoryStateSweeper");
        List<String> stores = List.of("baselineDataStore", "inMemoryDistributedLockService",
                "inMemoryProtectableRapidReentryRepository", "inMemoryAsyncSecurityContextProvider");

        assertThat(beanFactory.getBeanNamesForType(ExpiringStateStore.class)).containsAll(stores);
        // What the sweeper bean sweeps: the ExpiringStateStore beans, in order.
        List<ExpiringStateStore> storeBeans = stores.stream()
                .map(name -> beanFactory.getBean(name, ExpiringStateStore.class))
                .toList();
        assertThat(beanFactory.getBeanProvider(ExpiringStateStore.class).orderedStream().toList())
                .containsAll(storeBeans);
        InMemoryStateSweeper sweeper = beanFactory.getBean(InMemoryStateSweeper.class);
        try {
            sweeper.sweep();
        } finally {
            sweeper.close();
            beanFactory.destroySingletons();
        }
    }

    private static void register(DefaultListableBeanFactory beanFactory, String beanMethod) {
        RootBeanDefinition definition = new RootBeanDefinition();
        definition.setFactoryBeanName("configuration");
        definition.setFactoryMethodName(beanMethod);
        definition.setAutowireMode(AbstractBeanDefinition.AUTOWIRE_CONSTRUCTOR);
        beanFactory.registerBeanDefinition(beanMethod, definition);
    }

    private static Method beanMethod(String name) {
        return Arrays.stream(CoreAutonomousAutoConfiguration.class.getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Bean method not found: " + name));
    }
}
