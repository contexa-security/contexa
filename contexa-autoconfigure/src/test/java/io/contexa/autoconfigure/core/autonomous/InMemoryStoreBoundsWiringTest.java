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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.CompositeLlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.processor.ColdPathEventProcessor;
import io.contexa.contexacore.autonomous.processor.PromptShadowRunner;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityColdPathProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-42: the bound on users of the standalone decision store, the byte budget of the standalone context store's held
 * learning records and the bound on escalation protection windows come from their settings; without a setting the
 * decision store and the context store derive theirs from the maximum heap.
 */
class InMemoryStoreBoundsWiringTest {

    @Test
    void theStandaloneDecisionStoreTakesItsBoundOnUsersFromTheSetting() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getStandalone().setMaxDecisionUsers(1_234);
        properties.setAllowValidity(Duration.ofMinutes(12));

        InMemoryZeroTrustActionRepository configured =
                new CoreAutonomousAutoConfiguration().inMemoryZeroTrustActionRepository(provider(properties));
        InMemoryZeroTrustActionRepository derived = new CoreAutonomousAutoConfiguration()
                .inMemoryZeroTrustActionRepository(provider(new SecurityZeroTrustProperties()));
        InMemoryZeroTrustActionRepository withoutProperties = new CoreAutonomousAutoConfiguration()
                .inMemoryZeroTrustActionRepository(new DefaultListableBeanFactory()
                        .getBeanProvider(SecurityZeroTrustProperties.class));

        assertThat(configured.maxUsers()).isEqualTo(1_234);
        assertThat(configured.allowValidity()).isEqualTo(Duration.ofMinutes(12));
        assertThat(derived.allowValidity()).isEqualTo(ZeroTrustAction.ALLOW.getDefaultTtl());
        assertThat(withoutProperties.allowValidity()).isEqualTo(ZeroTrustAction.ALLOW.getDefaultTtl());
        assertThat(derived.maxUsers()).isEqualTo(new InMemoryZeroTrustActionRepository(0).maxUsers())
                .isBetween(1_000, 1_000_000);
        assertThat(withoutProperties.maxUsers()).isEqualTo(derived.maxUsers());
    }

    @Test
    void theStandaloneContextStoreTakesItsHeldLearningBudgetFromTheSetting() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        assertThat(properties.getStandalone().getMaxHeldLearningBytes()).isZero();
        properties.getStandalone().setMaxHeldLearningBytes(64L * 1024 * 1024);
        ObjectProvider<SecurityPlaneProperties> noPlaneProperties =
                new DefaultListableBeanFactory().getBeanProvider(SecurityPlaneProperties.class);

        InMemorySecurityContextDataStore configured = new CoreAutonomousAutoConfiguration()
                .inMemorySecurityContextDataStore(noPlaneProperties, provider(properties));
        InMemorySecurityContextDataStore derived = new CoreAutonomousAutoConfiguration()
                .inMemorySecurityContextDataStore(noPlaneProperties, provider(new SecurityZeroTrustProperties()));
        InMemorySecurityContextDataStore withoutProperties = new CoreAutonomousAutoConfiguration()
                .inMemorySecurityContextDataStore(noPlaneProperties, new DefaultListableBeanFactory()
                        .getBeanProvider(SecurityZeroTrustProperties.class));

        assertThat(configured.heldLearningBudgetBytes()).isEqualTo(64L * 1024 * 1024);
        assertThat(derived.heldLearningBudgetBytes())
                .isEqualTo(new InMemorySecurityContextDataStore().heldLearningBudgetBytes())
                .isBetween(16L * 1024 * 1024, 1024L * 1024 * 1024);
        assertThat(withoutProperties.heldLearningBudgetBytes()).isEqualTo(derived.heldLearningBudgetBytes());
    }

    @Test
    void theColdPathTakesItsBoundOnEscalationWindowsFromTheSetting() {
        SecurityColdPathProperties properties = new SecurityColdPathProperties();
        assertThat(properties.getMaxEscalationWindows()).isEqualTo(ColdPathEventProcessor.DEFAULT_MAX_ESCALATION_WINDOWS);
        properties.setMaxEscalationWindows(250);

        ColdPathEventProcessor processor = new CoreAutonomousEventAutoConfiguration().coldPathEventProcessor(
                null, null, new CompositeLlmAnalysisEventListener(List.of()),
                new DefaultListableBeanFactory().getBeanProvider(PromptShadowRunner.class), provider(properties));

        assertThat(processor.getMaxEscalationWindows()).isEqualTo(250);
    }

    private static <T> ObjectProvider<T> provider(T bean) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("bean", bean);
        @SuppressWarnings("unchecked")
        ObjectProvider<T> provider = (ObjectProvider<T>) beanFactory.getBeanProvider(bean.getClass());
        return provider;
    }
}
