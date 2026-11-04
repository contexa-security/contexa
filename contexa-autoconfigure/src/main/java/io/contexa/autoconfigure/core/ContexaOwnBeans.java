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
import org.springframework.beans.factory.BeanFactory;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.function.Supplier;

/**
 * Contexa's own beans of types that Spring Security (and Spring Boot) pick from the container by type for the application: they are hidden
 * from lookups by type and Contexa's code takes them by name, so that the application's own beans of those types are never replaced,
 * duplicated or taken in their place.
 */
public final class ContexaOwnBeans {

    public static final String PASSWORD_ENCODER = "contexaPasswordEncoder";
    public static final String ROLE_HIERARCHY = "contexaRoleHierarchy";

    private ContexaOwnBeans() {
    }

    /** The role hierarchy of Contexa's own policies and accounts, never the application's. */
    public static RoleHierarchy roleHierarchy(BeanFactory beanFactory) {
        return roleHierarchyImpl(beanFactory);
    }

    /** The same hierarchy as its implementation: the console reloads its rules, so the very instance the policies use is needed. */
    public static RoleHierarchyImpl roleHierarchyImpl(BeanFactory beanFactory) {
        return held(beanFactory, ROLE_HIERARCHY, RoleHierarchyImpl.class, RoleHierarchyImpl::new);
    }

    /** The encoder of Contexa's own accounts (the console administrator, agent client secrets): always the delegating encoder, never the application's. */
    public static PasswordEncoder passwordEncoder(BeanFactory beanFactory) {
        return held(beanFactory, PASSWORD_ENCODER, PasswordEncoder.class, PasswordEncoderFactories::createDelegatingPasswordEncoder);
    }

    /**
     * The bean of that name, which is a {@link HeldBean} (not of the shared type, see there), or the fallback when Contexa has none.
     * A bean of the shared type itself under that name is taken as well, as an application of Contexa's own may have declared it.
     */
    private static <T> T held(BeanFactory beanFactory, String name, Class<T> type, Supplier<T> fallback) {
        if (!beanFactory.containsBean(name)) {
            return fallback.get();
        }
        Object bean = beanFactory.getBean(name);
        if (bean instanceof HeldBean<?> holder && type.isInstance(holder.get())) {
            return type.cast(holder.get());
        }
        return type.isInstance(bean) ? type.cast(bean) : fallback.get();
    }
}
