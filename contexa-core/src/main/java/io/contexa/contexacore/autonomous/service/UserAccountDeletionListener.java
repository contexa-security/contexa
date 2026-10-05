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

import io.contexa.contexacommon.security.UserAccountDeletedEvent;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Purges the engine state of a deleted account once the deletion has committed. A rolled back deletion keeps the
 * account and therefore its state.
 */
public class UserAccountDeletionListener {

    private final UserEngineStatePurger purger;

    public UserAccountDeletionListener(UserEngineStatePurger purger) {
        this.purger = purger;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAccountDeleted(UserAccountDeletedEvent event) {
        if (event != null && event.username() != null && !event.username().isBlank()) {
            purger.purge(event.username());
        }
    }
}
