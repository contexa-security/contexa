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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

/**
 * The DECISION FACTS values a v20 prompt draws straight from the sealed canonical context: the same functions the
 * render uses, for the prompt inspector to compare the drawn lines with the sealed sources (R1b-2). The facts the
 * resolver decides are compared with the sealed decision facts by their own check.
 */
public final class DecisionFactLineValues {

    private DecisionFactLineValues() {
    }

    /** {@code ALLOW by policy P-7 v2}, or null; the render may add the host's unsealed provenance in brackets. */
    public static String authorizationEffect(CanonicalSecurityContext.Authorization authorization) {
        return SecurityDecisionPromptValues.authorizationEffectPart(authorization);
    }

    /** {@code method failed with X after authorization}, or null. */
    public static String methodFailure(CanonicalSecurityContext.Authorization authorization) {
        return SecurityDecisionPromptValues.methodFailurePart(authorization);
    }

    /** {@code break-glass declared (company record)}, or null. */
    public static String breakGlass(CanonicalSecurityContext.FrictionProfile friction) {
        return SecurityDecisionPromptValues.breakGlass(friction);
    }

    /** {@code bot UA: no; missing referer: yes}, or null. */
    public static String clientSignals(CanonicalSecurityContext.Intent intent) {
        return SecurityDecisionPromptValues.clientSignals(intent);
    }

    /** {@code blocked (session record); blocked (company record)}, or null. */
    public static String blockedUser(CanonicalSecurityContext canonical) {
        return SecurityDecisionPromptValues.blockedUser(canonical);
    }

    /** {@code none}, or {@code active, window open, ...}. */
    public static String temporaryElevation(CanonicalSecurityContext.RoleScopeProfile roleScope) {
        return SecurityDecisionPromptValues.temporaryElevation(roleScope);
    }
}
