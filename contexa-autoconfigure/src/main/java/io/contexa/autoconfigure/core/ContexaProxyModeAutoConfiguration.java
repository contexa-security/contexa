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
package io.contexa.autoconfigure.core;

import org.springframework.aop.config.AopConfigUtils;
import org.springframework.aop.framework.autoproxy.AutoProxyUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Contexa's beans are proxied by class; the application's beans are proxied the way the application chose.
 * <p>
 * Contexa used to force class proxies for the whole application ({@code @EnableAspectJAutoProxy(proxyTargetClass = true)}), which
 * stops an application that chose JDK proxies (a {@code final} class behind an interface, for one) from starting. The beans Contexa
 * defines now carry the {@link AutoProxyUtils#PRESERVE_TARGET_CLASS_ATTRIBUTE} attribute, which Spring reads for that bean alone, so
 * they keep the proxies they had and every other bean follows {@code spring.aop.proxy-target-class} and the application's own
 * {@code @EnableAspectJAutoProxy}.
 */
@AutoConfiguration
@Import(ContexaProxyModeAutoConfiguration.InfrastructureProxying.class)
public class ContexaProxyModeAutoConfiguration {

    /** The packages of the Contexa libraries (the applications that use them, and the applications of Contexa's own, are others). */
    static final String[] CONTEXA_PACKAGES = {"io.contexa.contexa", "io.contexa.autoconfigure"};

    @Bean(name = "contexaProxyModePostProcessor")
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static BeanFactoryPostProcessor contexaProxyModePostProcessor() {
        return beanFactory -> {
            for (String name : beanFactory.getBeanDefinitionNames()) {
                BeanDefinition definition = beanFactory.getBeanDefinition(name);
                if (definedByContexa(definition)) {
                    definition.setAttribute(AutoProxyUtils.PRESERVE_TARGET_CLASS_ATTRIBUTE, Boolean.TRUE);
                }
            }
        };
    }

    /**
     * Contexa's advisors are of the infrastructure role. This creator applies those and none of the application's aspects:
     * it does not depend on {@code spring.aop.auto}, and it does not override that setting either.
     */
    static final class InfrastructureProxying implements ImportBeanDefinitionRegistrar {

        @Override
        public void registerBeanDefinitions(AnnotationMetadata metadata, BeanDefinitionRegistry registry) {
            AopConfigUtils.registerAutoProxyCreatorIfNecessary(registry);
        }
    }

    static boolean definedByContexa(BeanDefinition definition) {
        if (inContexaPackage(definition.getBeanClassName())) {
            return true;
        }
        return definition instanceof AnnotatedBeanDefinition annotated
                && annotated.getFactoryMethodMetadata() != null
                && inContexaPackage(annotated.getFactoryMethodMetadata().getDeclaringClassName());
    }

    private static boolean inContexaPackage(String className) {
        if (className == null) {
            return false;
        }
        for (String prefix : CONTEXA_PACKAGES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
