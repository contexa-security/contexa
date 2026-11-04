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

import io.contexa.contexacommon.security.HeldBean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring Security looks a {@code PasswordEncoder} and a {@code RoleHierarchy} up for the application by type
 * ({@code getBeanProvider(T).getIfUnique()}), and a bean that is the only one of the type is found even when it is not an autowire
 * candidate. Contexa's own are held in a {@link HeldBean}, so that the application's login and authorization never use them (found by the
 * hostile host: the look-up gave Contexa's encoder and Contexa's role hierarchy to an application that had none of its own).
 */
class ContexaOwnBeansTest {

    private static DefaultListableBeanFactory factoryWithAHiddenEncoderAndHierarchy(Object encoder, Object hierarchy) {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        factory.registerBeanDefinition(ContexaOwnBeans.PASSWORD_ENCODER, definition(encoder));
        factory.registerBeanDefinition(ContexaOwnBeans.ROLE_HIERARCHY, definition(hierarchy));
        return factory;
    }

    @SuppressWarnings("unchecked")
    private static <T> RootBeanDefinition definition(T instance) {
        RootBeanDefinition definition = new RootBeanDefinition((Class<T>) instance.getClass(), () -> instance);
        definition.setAutowireCandidate(false);
        return definition;
    }

    @Test
    @DisplayName("control: a hidden bean of the shared type is still found by the frameworks' look-up when it is the only one")
    void aHiddenSoleBeanOfTheSharedTypeIsStillFound() {
        PasswordEncoder own = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        RoleHierarchyImpl ownHierarchy = new RoleHierarchyImpl();
        DefaultListableBeanFactory factory = factoryWithAHiddenEncoderAndHierarchy(own, ownHierarchy);

        assertThat(factory.getBeanProvider(PasswordEncoder.class).getIfUnique()).isSameAs(own);
        assertThat(factory.getBeanProvider(RoleHierarchy.class).getIfUnique()).isSameAs(ownHierarchy);
    }

    @Test
    @DisplayName("held in a HeldBean, the frameworks' look-ups find nothing and Contexa's code takes the very instance by name")
    void heldBeansAreFoundByNameOnly() {
        PasswordEncoder own = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        RoleHierarchyImpl ownHierarchy = new RoleHierarchyImpl();
        DefaultListableBeanFactory factory = factoryWithAHiddenEncoderAndHierarchy(new HeldBean<>(own), new HeldBean<>(ownHierarchy));

        assertThat(factory.getBeanProvider(PasswordEncoder.class).getIfUnique()).isNull();
        assertThat(factory.getBeanProvider(RoleHierarchy.class).getIfUnique()).isNull();
        assertThat(ContexaOwnBeans.passwordEncoder(factory)).isSameAs(own);
        assertThat(ContexaOwnBeans.roleHierarchy(factory)).isSameAs(ownHierarchy);
        assertThat(ContexaOwnBeans.roleHierarchyImpl(factory)).as("the console reloads this very instance").isSameAs(ownHierarchy);
    }

    @Test
    @DisplayName("an application with its own encoder and hierarchy keeps them, and Contexa still has its own")
    void theApplicationsOwnBeansAreNotReplaced() {
        PasswordEncoder own = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        PasswordEncoder applications = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        RoleHierarchyImpl applicationsHierarchy = new RoleHierarchyImpl();
        DefaultListableBeanFactory factory = factoryWithAHiddenEncoderAndHierarchy(new HeldBean<>(own), new HeldBean<>(new RoleHierarchyImpl()));
        factory.registerSingleton("applicationsEncoder", applications);
        factory.registerSingleton("applicationsHierarchy", applicationsHierarchy);

        assertThat(factory.getBeanProvider(PasswordEncoder.class).getIfUnique()).isSameAs(applications);
        assertThat(factory.getBeanProvider(RoleHierarchy.class).getIfUnique()).isSameAs(applicationsHierarchy);
        assertThat(ContexaOwnBeans.passwordEncoder(factory)).isSameAs(own);
    }

    @Test
    @DisplayName("without Contexa's beans the code gets an encoder and a hierarchy of its own")
    void withoutContexasBeansAFallbackIsGiven() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();

        assertThat(ContexaOwnBeans.passwordEncoder(factory)).isNotNull();
        assertThat(ContexaOwnBeans.roleHierarchy(factory)).isNotNull();
    }
}
