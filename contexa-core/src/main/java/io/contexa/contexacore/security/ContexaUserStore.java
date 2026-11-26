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

import io.contexa.contexacommon.security.HeldBean;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.function.BooleanSupplier;

/**
 * The user stores of Contexa's sign-in. Contexa's own store exists in every way of running Contexa. It is a bean of the
 * type only where Contexa's main chain signs the application's users in and the application has no store of its own;
 * elsewhere it is held ({@link HeldBean}), so that Spring's lookups by type for the application never find it, and it is
 * taken here by its name ({@link #own}).
 * <p>
 * Contexa's own accounts sign in from Contexa's store ({@link #forSignIn}): the application's users are not Contexa's
 * accounts, and a store of the application's would not know the administrator. What Contexa asks about the application's
 * users (a code or a key of theirs) goes to the application's store as {@link #of} says.
 */
public final class ContexaUserStore {

    public static final String BEAN_NAME = "contexaUnifiedUserDetailsService";

    private ContexaUserStore() {
    }

    /** Contexa's own store, whether it is a bean of the type or held; {@code null} where Contexa has none. */
    @Nullable
    public static UserDetailsService own(BeanFactory beanFactory) {
        if (!beanFactory.containsBean(BEAN_NAME)) {
            return null;
        }
        Object bean = beanFactory.getBean(BEAN_NAME);
        if (bean instanceof HeldBean<?> holder && holder.get() instanceof UserDetailsService store) {
            return store;
        }
        return bean instanceof UserDetailsService store ? store : null;
    }

    /**
     * The store that names the user of a token, and the user of the application's own sign-in when Contexa asks of it:
     * the application's when it has exactly one or marks one primary, else Contexa's.
     */
    public static UserDetailsService of(BeanFactory beanFactory) {
        UserDetailsService application = beanFactory.getBeanProvider(UserDetailsService.class).getIfUnique();
        if (application != null) {
            return application;
        }
        UserDetailsService own = own(beanFactory);
        return own != null ? own : beanFactory.getBean(BEAN_NAME, UserDetailsService.class);
    }

    /**
     * The store of Contexa's own sign-in (the form and the first step of MFA, the code, the passkey and the sign-in by REST):
     * Contexa's own, whatever stores the application declares, so that Contexa's accounts sign in and the application's
     * users are refused as any name nobody holds is. Without a store of Contexa's the answer is that of {@link #of}.
     */
    public static UserDetailsService forSignIn(BeanFactory beanFactory) {
        UserDetailsService own = own(beanFactory);
        return own != null ? own : of(beanFactory);
    }

    /**
     * Whether Contexa's own store is the one that names the users of tokens: then a user a token of the sign-in names is one of
     * Contexa's accounts. Asked when first needed, once the application's beans exist, and answered the same from then on;
     * while the stores cannot be told the answer is no.
     */
    public static BooleanSupplier signsInWithContexaAccounts(BeanFactory beanFactory) {
        return new BooleanSupplier() {
            private volatile Boolean answer;

            @Override
            public boolean getAsBoolean() {
                Boolean known = answer;
                if (known == null) {
                    try {
                        UserDetailsService own = own(beanFactory);
                        known = own != null && of(beanFactory) == own;
                    } catch (RuntimeException unknown) {
                        // a store that cannot be told now: no account is assumed, and it is asked again next time
                        return false;
                    }
                    answer = known;
                }
                return known;
            }
        };
    }
}
