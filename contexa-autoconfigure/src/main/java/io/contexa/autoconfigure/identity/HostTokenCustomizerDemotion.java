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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.ArrayList;
import java.util.List;

/**
 * Makes room for Contexa's token checks beside the application's own token customizers. The authorization server takes
 * exactly one {@code OAuth2TokenCustomizer<JwtEncodingContext>} bean, so an application that declared its own used to
 * replace Contexa's, and with it the refusal of a suspended agent, the checks on the renewal of a person's token and the
 * rules of a token exchange. Here every such bean of the application is taken out of that bean type and kept as a
 * {@link HostTokenCustomizer} under the same name, with its definition as an inner bean (so it is created as before, with
 * what it asks for, but is no bean of that type); Contexa's {@link ComposedTokenCustomizer} then is the only one the
 * server finds and runs the application's customizers after its own checks.
 * <p>
 * Nothing is done when Contexa's composed customizer is not the bean named {@value #COMPOSED_BEAN}: an application that
 * declared a bean of that name took the place on purpose, and its customizers stay as they are.
 */
@Slf4j
final class HostTokenCustomizerDemotion implements BeanFactoryPostProcessor {

    static final String COMPOSED_BEAN = "contexaTokenCustomizer";

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        if (!(beanFactory instanceof BeanDefinitionRegistry registry) || !composedByContexa(beanFactory)) {
            return;
        }
        ResolvableType serverLookup = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class,
                JwtEncodingContext.class);
        List<String> kept = new ArrayList<>();
        for (String name : beanFactory.getBeanNamesForType(serverLookup, true, false)) {
            if (COMPOSED_BEAN.equals(name) || !registry.containsBeanDefinition(name)) {
                continue;
            }
            Order order = beanFactory.findAnnotationOnBean(name, Order.class, false);
            BeanDefinition definition = registry.getBeanDefinition(name);
            RootBeanDefinition wrapper = new RootBeanDefinition(HostTokenCustomizer.class);
            wrapper.getConstructorArgumentValues().addIndexedArgumentValue(0,
                    new BeanDefinitionHolder(definition, name + "#applicationTokenCustomizer"));
            wrapper.getConstructorArgumentValues().addIndexedArgumentValue(1,
                    order != null ? order.value() : Ordered.LOWEST_PRECEDENCE);
            registry.removeBeanDefinition(name);
            registry.registerBeanDefinition(name, wrapper);
            kept.add(name);
        }
        if (!kept.isEmpty()) {
            log.info("[OAuth2] The authorization server takes one token customizer, so Contexa composed the application's {} "
                    + "to run after its own token checks (agent suspension, renewal, token exchange).", kept);
        }
    }

    private static boolean composedByContexa(ConfigurableListableBeanFactory beanFactory) {
        if (!beanFactory.containsBeanDefinition(COMPOSED_BEAN)) {
            return false;
        }
        Class<?> type = beanFactory.getType(COMPOSED_BEAN, false);
        return type != null && ComposedTokenCustomizer.class.isAssignableFrom(type);
    }
}
