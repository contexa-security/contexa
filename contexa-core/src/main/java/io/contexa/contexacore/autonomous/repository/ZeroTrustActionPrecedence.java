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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.time.Duration;
import java.util.Map;

/**
 * Precedence rules shared by the repository implementations.
 *
 * <p>Decisions are stored per user while analysis runs per user session. Only ALLOW is bound to
 * the analysed context. BLOCK, ESCALATE and CHALLENGE restrict the user in every session: no less
 * strict final result lifts an active one, whichever session or request it was analysed for, so
 * when several decisions come out for one user the restriction is the one in force (RL-13). A
 * CHALLENGE is lifted by the MFA its challenge started, for the session that answered it alone (Q-12),
 * an ESCALATE only by an approved override (a review, Q-87), a BLOCK only by the administrator's
 * approval; all three by a stricter decision.
 * A CHALLENGE also lapses with its TTL; an ESCALATE whose TTL ends without resolution is promoted to
 * BLOCK by the access filter. That holds with allow-escalate-final-action on; off, an ESCALATE is
 * internal to the analysis, and one left in the store ends as the terminal action when it is read.</p>
 */
public final class ZeroTrustActionPrecedence {

    private ZeroTrustActionPrecedence() {
    }

    /**
     * What a stored ESCALATE is replaced with, given the terminal action; null keeps it. A BLOCK is not
     * stored by a read: it also needs its flag and its record, which the access filter writes.
     */
    static ZeroTrustAction storedEscalateReplacement(ZeroTrustAction terminalAction) {
        return terminalAction != ZeroTrustAction.BLOCK ? terminalAction : null;
    }

    /**
     * Returns whether the action only applies to the context it was decided for, so that another
     * context needs a fresh analysis.
     */
    static boolean isContextBound(ZeroTrustAction action) {
        return action == ZeroTrustAction.ALLOW;
    }

    /**
     * Returns whether a final analysis result must not replace the active action because the
     * active action is a user-level BLOCK, CHALLENGE or ESCALATE and the result is less strict.
     */
    public static boolean keepsActiveRestriction(ZeroTrustAction active, ZeroTrustAction incoming) {
        return (active == ZeroTrustAction.BLOCK || active == ZeroTrustAction.CHALLENGE
                || active == ZeroTrustAction.ESCALATE)
                && incoming != null
                && strictness(incoming) < strictness(active);
    }

    /**
     * The same with what is known of the two decisions (Q-5). A CHALLENGE no model decided holds until the model
     * decides: an ALLOW of the model replaces it, an action no model reached does not. A CHALLENGE no model decided
     * never replaces one the model decided, which it would shorten; it renews one like itself.
     *
     * @param activeIsTechnical whether the active action is a CHALLENGE no model decided
     * @param incomingFields    the fields of the incoming decision
     */
    static boolean keepsActiveRestriction(ZeroTrustAction active, boolean activeIsTechnical, ZeroTrustAction incoming,
                                          Map<String, Object> incomingFields) {
        if (active != ZeroTrustAction.CHALLENGE || incoming == null) {
            return keepsActiveRestriction(active, incoming);
        }
        if (activeIsTechnical) {
            return keepsActiveRestriction(active, incoming) && !decidedByTheModel(incomingFields);
        }
        return keepsActiveRestriction(active, incoming) || isTechnicalChallenge(incoming, incomingFields);
    }

    /** Whether the decision is a CHALLENGE no model decided. */
    static boolean isTechnicalChallenge(ZeroTrustAction action, Map<String, Object> fields) {
        return action == ZeroTrustAction.CHALLENGE && fields != null
                && Boolean.TRUE.equals(fields.get(ZeroTrustActionRepository.TECHNICAL_CHALLENGE));
    }

    /** The TTL of the decision: a CHALLENGE no model decided lasts a short time, any other action its own TTL. */
    static Duration ttlOf(ZeroTrustAction action, Map<String, Object> fields) {
        return isTechnicalChallenge(action, fields) ? ZeroTrustActionRepository.TECHNICAL_CHALLENGE_TTL
                : action.getDefaultTtl();
    }

    private static boolean decidedByTheModel(Map<String, Object> fields) {
        return fields != null && Boolean.TRUE.equals(fields.get(ZeroTrustActionRepository.LLM_DECISION_PRESENT));
    }

    private static int strictness(ZeroTrustAction action) {
        return switch (action) {
            case BLOCK -> 3;
            case ESCALATE -> 2;
            case CHALLENGE -> 1;
            case ALLOW, PENDING_ANALYSIS -> 0;
        };
    }
}
