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
package io.contexa.contexaiam.admin.promptquality.cases;

import io.contexa.contexacommon.security.UserAccountDeletedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.Objects;

/**
 * Quality plan 3.2: the deletion of a person reaches the labelled cases whose decision is the person's, once the
 * deletion has committed. A case holds the person's addresses, devices and baselines, and outlives the sealed
 * decision it was made from, so it goes with the person.
 */
public class QualityCaseUserDeletionListener {

    private static final Logger log = LoggerFactory.getLogger(QualityCaseUserDeletionListener.class);

    private final PromptQualityCases cases;

    public QualityCaseUserDeletionListener(PromptQualityCases cases) {
        this.cases = Objects.requireNonNull(cases, "cases");
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAccountDeleted(UserAccountDeletedEvent event) {
        if (event == null || event.username() == null || event.username().isBlank()) {
            return;
        }
        try {
            cases.deleteSubject(event.username());
        }
        catch (RuntimeException failure) {
            log.error("[PromptQualityCase] The cases of deleted account {} could not be removed", event.accountId(),
                    failure);
        }
    }
}
