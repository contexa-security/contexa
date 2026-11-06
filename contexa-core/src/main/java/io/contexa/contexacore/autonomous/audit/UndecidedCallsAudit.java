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
package io.contexa.contexacore.autonomous.audit;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.store.ContexaStores;

import java.util.Map;
import java.util.function.Consumer;

/**
 * Q-7: an interval in which protected calls went on and nothing decided them stays on record. A later reader of the
 * decisions would otherwise take the gap for calls that were never made.
 */
public final class UndecidedCallsAudit implements Consumer<ContexaStores.UndecidedCalls> {

    private final CentralAuditFacade audit;

    public UndecidedCallsAudit(CentralAuditFacade audit) {
        this.audit = audit;
    }

    @Override
    public void accept(ContexaStores.UndecidedCalls calls) {
        audit.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.SECURITY_ERROR)
                .principalName("SYSTEM")
                .eventSource("CORE")
                .resourceIdentifier("ContexaStores")
                .resourceUri("/errors/ContexaStores")
                .action("PROTECTED_CALLS_WITHOUT_DECISION")
                .decision("NO_DECISION")
                .outcome("STORE_UNAVAILABLE")
                .reason(calls.calls() + " protected calls went on without a decision between " + calls.from()
                        + " and " + calls.to() + ": a store Contexa decides with did not answer.")
                .details(Map.of("from", calls.from().toString(), "to", calls.to().toString(), "calls", calls.calls()))
                .build());
    }
}
