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
package io.contexa.autoconfigure.ai;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.type.MethodMetadata;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.List;

/**
 * Reports a host-owned application whose only Spring Security filter chains are the ones Spring Boot
 * creates when no SecurityFilterChain is declared. In HOST_OWNED mode Contexa builds no chain, so such
 * an application runs under Spring Boot's default security, which requires authentication for every
 * request. The host has to declare its own SecurityFilterChain, or set contexa.bridge.ownership to
 * CONTEXA_OWNED so that Contexa owns authentication.
 */
@Slf4j
public class HostOwnedSecurityChainDiagnostics implements SmartInitializingSingleton {

    static final List<String> SPRING_BOOT_DEFAULT_CHAIN_SOURCES = List.of(
            "org.springframework.boot.autoconfigure.security.servlet.SpringBootWebSecurityConfiguration",
            "org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration");

    private final ConfigurableListableBeanFactory beanFactory;

    public HostOwnedSecurityChainDiagnostics(ConfigurableListableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (onlySpringBootDefaultChains()) {
            log.error("[Contexa] HOST_OWNED mode: no SecurityFilterChain is declared by the application, so Spring Boot's "
                    + "default security is active and every request requires authentication. Contexa does not build "
                    + "a chain in HOST_OWNED mode. Declare the application's own SecurityFilterChain (for example "
                    + "anyRequest().permitAll() to keep existing legacy access rules), or set "
                    + "contexa.bridge.ownership=CONTEXA_OWNED to let Contexa own authentication.");
        }
    }

    boolean onlySpringBootDefaultChains() {
        String[] chainNames = beanFactory.getBeanNamesForType(SecurityFilterChain.class, true, false);
        return chainNames.length > 0 && Arrays.stream(chainNames).allMatch(this::isSpringBootDefaultChain);
    }

    private boolean isSpringBootDefaultChain(String beanName) {
        if (!beanFactory.containsBeanDefinition(beanName)) {
            return false;
        }
        BeanDefinition definition = beanFactory.getBeanDefinition(beanName);
        if (!(definition instanceof AnnotatedBeanDefinition annotated)) {
            return false;
        }
        MethodMetadata factoryMethod = annotated.getFactoryMethodMetadata();
        if (factoryMethod == null) {
            return false;
        }
        String declaringClass = factoryMethod.getDeclaringClassName();
        return SPRING_BOOT_DEFAULT_CHAIN_SOURCES.stream().anyMatch(declaringClass::startsWith);
    }
}
