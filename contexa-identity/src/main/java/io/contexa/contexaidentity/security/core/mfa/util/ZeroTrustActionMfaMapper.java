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
package io.contexa.contexaidentity.security.core.mfa.util;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;

public final class ZeroTrustActionMfaMapper {

    private ZeroTrustActionMfaMapper() {}

    /**
     * What a stored decision means for the second step of a new sign-in. The decision was reached for another request and
     * the store keeps it by user, without the session, address and browser of this sign-in, so an ALLOW in it waives
     * nothing: a stolen password would meet no second step while the victim's ALLOW lasts. A restriction holds for the
     * user wherever the sign-in comes from.
     */
    public static MfaDecision.DecisionType toDecisionType(ZeroTrustAction action) {
        if (action == null) {
            return MfaDecision.DecisionType.CHALLENGED;
        }
        return switch (action) {
            case ALLOW, CHALLENGE, PENDING_ANALYSIS -> MfaDecision.DecisionType.CHALLENGED;
            case BLOCK -> MfaDecision.DecisionType.BLOCKED;
            case ESCALATE -> MfaDecision.DecisionType.ESCALATED;
        };
    }
}
