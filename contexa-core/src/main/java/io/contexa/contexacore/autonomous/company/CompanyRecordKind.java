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
package io.contexa.contexacore.autonomous.company;

import org.springframework.lang.Nullable;

import java.util.Locale;

/**
 * The kinds of company record Contexa keeps (docs/agent OC-2). The six kinds a request is judged with carry the names
 * of {@code FrictionProfile.RECORD_*}; the company states which of them it integrates, so a kind it does not integrate
 * stays "not looked up" rather than "none found".
 */
public enum CompanyRecordKind {

    /** A person the company knows, with the id its own records name the person by. */
    PERSON(false),
    /** A person's assignment to a target, or the account manager of one. */
    ASSIGNMENT(true),
    /** An approval of work on a target. */
    APPROVAL(true),
    /** A ticket of the company's ticket system. */
    TICKET(true),
    /** An on-call shift. */
    ON_CALL(true),
    /** A registered business trip with the network the traveller works from. */
    TRAVEL(true),
    /** A day on which a person worked on a target. */
    ACCESS_HISTORY(true),
    /** Items the application delivered to a person from a target, counted against the person's approvals. */
    USAGE(false),
    /** A company rule: which requests it covers, what covers them and its exceptions. */
    POLICY(false),
    /** A company network (CIDR) and its zone. */
    NETWORK(false),
    /** A kind of record the company integrates, stated without a record of it. */
    SOURCE(false);

    private final boolean lookedUp;

    CompanyRecordKind(boolean lookedUp) {
        this.lookedUp = lookedUp;
    }

    /** Whether the kind is one a request is checked against ("looked up"), as {@code checkedRecordKinds} names it. */
    public boolean lookedUp() {
        return lookedUp;
    }

    /** The kind a name stands for, ignoring case and dashes; null for none. */
    @Nullable
    public static CompanyRecordKind of(@Nullable String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        String normalized = name.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        for (CompanyRecordKind kind : values()) {
            if (kind.name().equals(normalized)) {
                return kind;
            }
        }
        return null;
    }
}
