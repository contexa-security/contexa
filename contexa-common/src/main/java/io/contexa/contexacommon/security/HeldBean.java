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
package io.contexa.contexacommon.security;

import java.util.Objects;

/**
 * Holds a bean of Contexa's own whose type is one that Spring Security and Spring Boot pick from the application context <em>by type</em> for
 * the application (a {@code PasswordEncoder}, a {@code RoleHierarchy}). A bean of such a type is found by their look-ups
 * ({@code getBeanProvider(T).getIfUnique()}, {@code getBean(T.class)}) when it is the only one, even if it is not an autowire candidate;
 * the application's login or authorization would then use Contexa's. Held in this class the bean is of no shared type, and Contexa's code
 * takes it by the bean's name.
 */
public final class HeldBean<T> {

    private final T bean;

    public HeldBean(T bean) {
        this.bean = Objects.requireNonNull(bean, "bean");
    }

    public T get() {
        return bean;
    }
}
