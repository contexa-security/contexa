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
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Carries a change of accounts to the sessions that are open, once it has committed (Q-14): a session reading its
 * account before the commit would keep the old account under the new version, and a change rolled back changes nothing.
 */
@Slf4j
public class UserAccountChangeListener {

    private static final String DISABLED = "ACCOUNT_DISABLED";
    private static final String PASSWORD_CHANGED = "PASSWORD_CHANGED";

    private final ObjectProvider<SecurityContextDataStore> store;
    private final ObjectProvider<IForceLogoutService> forceLogout;
    /** The version did not move on because Redis was away; it does once Redis is back. */
    private final AtomicBoolean versionOwed = new AtomicBoolean();

    public UserAccountChangeListener(ObjectProvider<SecurityContextDataStore> store,
                                     ObjectProvider<IForceLogoutService> forceLogout) {
        this.store = store;
        this.forceLogout = forceLogout;
    }

    /** A change of accounts Redis did not take reaches the open sessions once Redis is back. */
    public void setContexaStores(ContexaStores stores) {
        stores.redis().whenBack(this::advanceOwedVersion);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAuthoritiesChanged(UserAuthoritiesChangedEvent event) {
        advanceVersion();
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAccountDisabled(UserAccountDisabledEvent event) {
        endWhatIsOpen(event.username(), DISABLED);
    }

    /** The change stands whatever happens here: the worst a store that is down can do is leave what is open running. */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onPasswordChanged(UserPasswordChangedEvent event) {
        endWhatIsOpen(event.username(), PASSWORD_CHANGED);
    }

    /**
     * Ends what the account has open at once: its sessions, and the tokens the forced logout reaches. The version moves
     * on as well, so a session the forced logout does not know ends on its next request.
     */
    private void endWhatIsOpen(String username, String reason) {
        advanceVersion();
        IForceLogoutService logout = forceLogout.getIfAvailable();
        if (logout == null || username == null || username.isBlank()) {
            return;
        }
        try {
            logout.forceLogoutByUserId(username, reason);
        } catch (RuntimeException e) {
            log.error("[UserAccountChange] Failed to end what an account has open: userId={}, reason={}", username, reason, e);
        }
    }

    private void advanceOwedVersion() {
        if (versionOwed.compareAndSet(true, false)) {
            advanceVersion();
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
            if (StoreFailures.isStoreFailure(e)) {
                versionOwed.set(true);
            }
            log.error("[UserAccountChange] Failed to tell open sessions that accounts changed", e);
        }
    }
}
