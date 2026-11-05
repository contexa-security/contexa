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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.security.UserAccountDisabledEvent;
import io.contexa.contexacommon.security.UserAuthoritiesChangedEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** Q-14: a change of accounts, once committed, reaches what is open. */
class UserAccountChangeListenerTest {

    private final InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
    private final IForceLogoutService forceLogout = mock(IForceLogoutService.class);

    private UserAccountChangeListener listener(boolean withForceLogout) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("store", store);
        if (withForceLogout) {
            beans.addBean("forceLogout", forceLogout);
        }
        ObjectProvider<SecurityContextDataStore> stores = beans.getBeanProvider(SecurityContextDataStore.class);
        ObjectProvider<IForceLogoutService> logouts = beans.getBeanProvider(IForceLogoutService.class);
        return new UserAccountChangeListener(stores, logouts);
    }

    @Test
    @DisplayName("a change of rights moves the version on")
    void aChangeOfRights() {
        long before = store.authoritiesVersion();

        listener(true).onAuthoritiesChanged(new UserAuthoritiesChangedEvent());

        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("a disabled account is logged out everywhere the forced logout reaches, and the rest ends on its next request")
    void aDisabledAccount() {
        long before = store.authoritiesVersion();

        listener(true).onAccountDisabled(new UserAccountDisabledEvent("alice"));

        verify(forceLogout).forceLogoutByUserId("alice", "ACCOUNT_DISABLED");
        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("without a forced logout the version still moves on")
    void withoutAForcedLogout() {
        long before = store.authoritiesVersion();

        listener(false).onAccountDisabled(new UserAccountDisabledEvent("alice"));

        assertThat(store.authoritiesVersion()).isGreaterThan(before);
    }

    @Test
    @DisplayName("a forced logout that fails does not fail the administrator's change")
    void aFailingLogoutStaysAnError() {
        doThrow(new IllegalStateException("store down")).when(forceLogout).forceLogoutByUserId(anyString(), anyString());

        assertThatCode(() -> listener(true).onAccountDisabled(new UserAccountDisabledEvent("alice")))
                .doesNotThrowAnyException();
    }
}
