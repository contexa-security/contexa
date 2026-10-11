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
package io.contexa.contexacore.autonomous.context.decision;

import java.util.List;

/**
 * One company record checked at the time of the request (W2-5).
 *
 * @param recordId   the record's ID ({@code APR-...}, {@code TCK-...})
 * @param kind       APPROVAL or TICKET
 * @param valid      whether the record covers the request at the request time: nothing fails it and nothing it
 *                   needs is unknown
 * @param failures   why it does not, in the order of {@link PolicyReason}; empty when valid
 * @param notes      each failure in words ({@code decided 20 min after this request}), in the same order
 * @param usedBefore the items the session already exported under the record before this request, null when the
 *                   record sets no limit or the count cannot be made
 * @param claimFalse whether the requester named the record and it does not exist
 * @param unknowns   what the engine could not check, in words; a record that nothing fails but with an unknown is
 *                   neither valid nor failed (P2 correction 3)
 */
public record RecordCheck(
        String recordId,
        String kind,
        boolean valid,
        List<PolicyReason> failures,
        List<String> notes,
        Integer usedBefore,
        boolean claimFalse,
        List<String> unknowns) {

    public static final String APPROVAL = "APPROVAL";
    public static final String TICKET = "TICKET";

    public RecordCheck {
        failures = failures == null ? List.of() : List.copyOf(failures);
        notes = notes == null ? List.of() : List.copyOf(notes);
        unknowns = unknowns == null ? List.of() : List.copyOf(unknowns);
    }

    /** A check that leaves nothing unknown. */
    public RecordCheck(String recordId, String kind, boolean valid, List<PolicyReason> failures, List<String> notes,
                       Integer usedBefore, boolean claimFalse) {
        this(recordId, kind, valid, failures, notes, usedBefore, claimFalse, List.of());
    }

    /** Whether nothing fails the record but something it needs is not known. */
    public boolean undecided() {
        return failures.isEmpty() && !unknowns.isEmpty();
    }

    /** The first reason the record does not cover the request, null when it does. */
    public PolicyReason reason() {
        return failures.isEmpty() ? null : failures.get(0);
    }
}
