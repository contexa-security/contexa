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

import java.util.function.BooleanSupplier;

/**
 * The user stores of Contexa's sign-in. Where Contexa owns the sign-in its own accounts sign in, from Contexa's own store,
 * whatever user stores the application declares ({@link #forSignIn}): the application's users are not Contexa's accounts,
 * and a store of the application's would not know the administrator. Where the application keeps its sign-in there is no
 * such store, and the store of the application's serves what Contexa asks of it (a code or a key of its users) as {@link #of}
 * says: the application's store when it has exactly one, or marks one primary; with several and no choice among them Contexa
 * cannot pick one for it, so Contexa's own store serves and the start goes on.
 */
public final class ContexaUserStore {

    public static final String BEAN_NAME = "contexaUnifiedUserDetailsService";

    private ContexaUserStore() {
    }

    /**
     * The store that names the user of a token, and the user of the application's own sign-in when Contexa asks of it:
     * the application's when it has exactly one or marks one primary, else Contexa's.
     */
    public static UserDetailsService of(BeanFactory beanFactory) {
        UserDetailsService application = beanFactory.getBeanProvider(UserDetailsService.class).getIfUnique();
        return application != null ? application : beanFactory.getBean(BEAN_NAME, UserDetailsService.class);
    }

    /**
     * The store of Contexa's own sign-in (the form and the first step of MFA, the code, the passkey and the sign-in by REST):
     * Contexa's own wherever Contexa owns the sign-in, whatever stores the application declares, so that Contexa's accounts
     * sign in and the application's users are refused as any name nobody holds is. Where the application keeps its sign-in
     * Contexa's store does not exist and the answer is that of {@link #of}.
     */
    public static UserDetailsService forSignIn(BeanFactory beanFactory) {
        return beanFactory.containsBean(BEAN_NAME) ? beanFactory.getBean(BEAN_NAME, UserDetailsService.class) : of(beanFactory);
    }

    /**
     * Whether Contexa's own store is the one that names the users of tokens: then a user a token of the sign-in names is one of
     * Contexa's accounts. Asked when first needed, once the application's beans exist, and answered the same from then on;
     * where Contexa does not own the sign-in its store does not exist and the answer is no, as it is while the stores
     * cannot be told.
     */
    public static BooleanSupplier signsInWithContexaAccounts(BeanFactory beanFactory) {
        return new BooleanSupplier() {
            private volatile Boolean answer;

            @Override
            public boolean getAsBoolean() {
                Boolean known = answer;
                if (known == null) {
                    try {
                        known = beanFactory.containsBean(BEAN_NAME) && of(beanFactory) == beanFactory.getBean(BEAN_NAME);
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
