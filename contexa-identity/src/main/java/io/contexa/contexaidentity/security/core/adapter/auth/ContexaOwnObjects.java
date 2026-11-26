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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.security.HeldBean;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.lang.Nullable;

/**
 * Contexa's own objects of the types Spring Security and Spring Boot pick from the container by type for the application (the
 * decoder and encoder of tokens, the keys, the stores of the authorization server). Such a bean is held in a {@link HeldBean}
 * wherever the application could take it in place of its own (R-17 of docs/agent/운영모드-정상화-구현계획.md), so Contexa's code
 * takes it by its name and unwraps it here, and never asks the container for the type. A bean of the type itself under the
 * name is taken as well: Contexa's main chain offers it so where the application has none, and an application may replace
 * Contexa's on purpose by declaring a bean of that name.
 */
public final class ContexaOwnObjects {

    private ContexaOwnObjects() {
    }

    /** Contexa's object of that name, held or a bean of the type; {@code null} where there is none of that type. */
    @Nullable
    public static <T> T find(@Nullable BeanFactory beanFactory, String name, Class<T> type) {
        if (beanFactory == null || !beanFactory.containsBean(name)) {
            return null;
        }
        Object bean = beanFactory.getBean(name);
        if (bean instanceof HeldBean<?> holder) {
            return type.isInstance(holder.get()) ? type.cast(holder.get()) : null;
        }
        return type.isInstance(bean) ? type.cast(bean) : null;
    }

    /**
     * Contexa's object of that name for code that cannot do without it: where there is none, it fails as a missing bean of
     * that name does, so the callers that answered a missing bean before answer this the same way.
     */
    public static <T> T own(@Nullable BeanFactory beanFactory, String name, Class<T> type) {
        T object = find(beanFactory, name, type);
        if (object == null) {
            throw new NoSuchBeanDefinitionException(name, "Contexa's " + type.getSimpleName() + " is not there");
        }
        return object;
    }
}
