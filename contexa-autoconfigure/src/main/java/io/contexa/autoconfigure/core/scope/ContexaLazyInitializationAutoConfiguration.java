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

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * An application may switch on lazy initialization for all its beans ({@code spring.main.lazy-initialization=true}). Contexa's beans are
 * not created on first use: its message broker, schedulers, listeners and filters must be there when the application is, so they are left
 * out of the lazy initialization; the application's own beans stay lazy.
 */
@AutoConfiguration
public class ContexaLazyInitializationAutoConfiguration {

    @Bean(name = "contexaLazyInitializationExcludeFilter")
    static LazyInitializationExcludeFilter contexaLazyInitializationExcludeFilter() {
        return (beanName, beanDefinition, beanType) -> ownedByContexa(beanDefinition, beanType);
    }

    /** The bean is Contexa's when its class, or the configuration class whose method defines it, is in a Contexa package. */
    static boolean ownedByContexa(BeanDefinition beanDefinition, Class<?> beanType) {
        return ContexaPackages.owns(beanType)
                || ContexaPackages.owns(beanDefinition.getBeanClassName())
                || ContexaPackages.owns(beanDefinition.getFactoryBeanName());
    }
}
