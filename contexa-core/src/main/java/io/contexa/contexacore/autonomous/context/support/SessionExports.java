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
package io.contexa.contexacore.autonomous.context.support;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.lang.Nullable;

import java.util.Set;

/**
 * What an agent moved in its session so far, counted from the session's earlier decisions (A2-9, RL-6). The line of the
 * prompt that states the session's activity and the comparison of a delegation's own quantity limits read it from here,
 * so they cannot disagree about how many items were exported.
 */
public final class SessionExports {

    /** The outcomes of a request that did not run: it was refused. */
    public static final Set<String> REFUSED = Set.of(SessionDecisionRecord.AUTHORIZATION_DENIED, "BLOCK");

    private SessionExports() {
    }

    /** Whether the request ran: it was not refused. */
    public static boolean ran(@Nullable SessionDecisionRecord decision) {
        return decision != null && !(decision.outcome() != null && REFUSED.contains(decision.outcome()));
    }

    /** The items the session's earlier requests exported: the item counts of the exports that ran. */
    public static long exportedItems(@Nullable CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile narrative =
                context != null ? context.getSessionNarrativeProfile() : null;
        if (narrative == null || narrative.getSessionDecisions() == null) {
            return 0;
        }
        long exported = 0;
        for (SessionDecisionRecord decision : narrative.getSessionDecisions()) {
            if (ran(decision) && "EXPORT".equalsIgnoreCase(decision.actionFamily()) && decision.items() != null) {
                exported += decision.items();
            }
        }
        return exported;
    }
}
