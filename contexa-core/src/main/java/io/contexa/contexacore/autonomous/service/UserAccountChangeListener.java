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
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Carries a change of accounts to the sessions that are open, once it has committed (Q-14): a session reading its
 * account before the commit would keep the old account under the new version, and a change rolled back changes nothing.
 */
@Slf4j
public class UserAccountChangeListener {

    private static final String DISABLED = "ACCOUNT_DISABLED";

    private final ObjectProvider<SecurityContextDataStore> store;
    private final ObjectProvider<IForceLogoutService> forceLogout;

    public UserAccountChangeListener(ObjectProvider<SecurityContextDataStore> store,
                                     ObjectProvider<IForceLogoutService> forceLogout) {
        this.store = store;
        this.forceLogout = forceLogout;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAuthoritiesChanged(UserAuthoritiesChangedEvent event) {
        advanceVersion();
    }

    /**
     * Ends what the account has open at once: its sessions, and the tokens the forced logout reaches. The version moves
     * on as well, so a session the forced logout does not know ends on its next request.
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAccountDisabled(UserAccountDisabledEvent event) {
        advanceVersion();
        IForceLogoutService logout = forceLogout.getIfAvailable();
        if (logout == null || event.username() == null || event.username().isBlank()) {
            return;
        }
        try {
            logout.forceLogoutByUserId(event.username(), DISABLED);
        } catch (RuntimeException e) {
            log.error("[UserAccountChange] Failed to end the sessions of a disabled account: userId={}",
                    event.username(), e);
        }
    }

    private void advanceVersion() {
        SecurityContextDataStore dataStore = store.getIfAvailable();
        if (dataStore == null) {
            return;
        }
        try {
            dataStore.advanceAuthoritiesVersion();
        } catch (RuntimeException e) {
            log.error("[UserAccountChange] Failed to tell open sessions that accounts changed", e);
        }
    }
}
