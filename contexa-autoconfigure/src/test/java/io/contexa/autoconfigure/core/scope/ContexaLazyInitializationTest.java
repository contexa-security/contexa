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
package io.contexa.autoconfigure.core.scope;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.boot.LazyInitializationExcludeFilter;

import static org.assertj.core.api.Assertions.assertThat;

/** With lazy initialization on for the whole application, Contexa's beans are still created at start and the application's stay lazy. */
class ContexaLazyInitializationTest {

    private final LazyInitializationExcludeFilter filter = ContexaLazyInitializationAutoConfiguration.contexaLazyInitializationExcludeFilter();

    @Test
    void aBeanOfAContexaClassIsNotLazy() {
        GenericBeanDefinition definition = new GenericBeanDefinition();
        definition.setBeanClassName("io.contexa.contexacore.autonomous.SecurityPlaneAgent");

        assertThat(filter.isExcluded("x", definition, ContexaPackages.class)).isTrue();
    }

    @Test
    void aBeanContexasConfigurationMethodDefinesIsNotLazyWhateverItsType() {
        GenericBeanDefinition definition = new GenericBeanDefinition();
        definition.setFactoryBeanName("io.contexa.contexaiam.aiam.config.WebSocketConfig");

        assertThat(filter.isExcluded("stompWebSocketHandlerMapping", definition, Object.class)).isTrue();
    }

    @Test
    void aBeanOfTheApplicationStaysLazy() {
        GenericBeanDefinition definition = new GenericBeanDefinition();
        definition.setBeanClassName("com.legacyshop.OrderService");
        definition.setFactoryBeanName("com.legacyshop.ShopConfiguration");

        assertThat(filter.isExcluded("orderService", definition, String.class)).isFalse();
    }
}
