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

/**
 * Precedence rules shared by the repository implementations.
 *
 * <p>Decisions are stored per user while analysis runs per user session. Only ALLOW is bound to
 * the analysed context. BLOCK, ESCALATE and CHALLENGE restrict the user in every session: the
 * analysis of another session cannot lift an active ESCALATE or CHALLENGE. They are lifted by MFA
 * success, an approved override, a stricter decision or their TTL.</p>
 */
final class ZeroTrustActionPrecedence {

    private ZeroTrustActionPrecedence() {
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
     * active action is a user-level CHALLENGE or ESCALATE and the result is less strict.
     */
    static boolean keepsActiveRestriction(ZeroTrustAction active, ZeroTrustAction incoming) {
        return (active == ZeroTrustAction.CHALLENGE || active == ZeroTrustAction.ESCALATE)
                && incoming != null
                && strictness(incoming) < strictness(active);
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
