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
package io.contexa.contexacore;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import lombok.Builder;
import lombok.Getter;
import java.time.Instant;

@Getter
@Builder
public class AdminOverride {

    private final String overrideId;

    private final String requestId;

    private final String userId;

    private final String adminId;

    private final Instant timestamp;

    private final String originalAction;

    private final String overriddenAction;

    private final String reason;

    private final boolean approved;

    private final double originalRiskScore;

    private final double originalConfidence;

    public boolean canUpdateBaseline() {
        return approved && ZeroTrustAction.ALLOW.name().equalsIgnoreCase(overriddenAction);
    }

    @Override
    public String toString() {
        return String.format(
            "AdminOverride{overrideId='%s', requestId='%s', userId='%s', adminId='%s', " +
            "originalAction='%s', overriddenAction='%s', approved=%s}",
            overrideId, requestId, userId, adminId,
            originalAction, overriddenAction, approved
        );
    }
}
