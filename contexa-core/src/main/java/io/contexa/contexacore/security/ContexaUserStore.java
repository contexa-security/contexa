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
package io.contexa.contexacore.security;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * The user store of the sign-in Contexa owns. The application's store serves when it has exactly one, or marks one primary;
 * with several and no choice among them Contexa cannot pick one for it, so Contexa's own store serves and the start goes on.
 */
public final class ContexaUserStore {

    public static final String BEAN_NAME = "contexaUnifiedUserDetailsService";

    private ContexaUserStore() {
    }

    public static UserDetailsService of(BeanFactory beanFactory) {
        UserDetailsService application = beanFactory.getBeanProvider(UserDetailsService.class).getIfUnique();
        return application != null ? application : beanFactory.getBean(BEAN_NAME, UserDetailsService.class);
    }
}
