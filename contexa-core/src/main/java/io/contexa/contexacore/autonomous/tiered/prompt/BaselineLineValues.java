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

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;

import java.util.Map;
import java.util.Objects;

/**
 * The USER BASELINE values a v20 prompt draws from an observed baseline view alone, by entry name, and the parts of
 * the WorkProfile and Evidence lines drawn from the sealed view and trust profiles: the same functions the render uses,
 * for the prompt inspector to compare the drawn lines with the sealed sources (R1b-2).
 */
public final class BaselineLineValues {

    /** The baseline state of a user of whom nothing personal is known (N-MISS-1 D1): every usual line is not learned. */
    public static final String NONE = "NONE";

    private BaselineLineValues() {
    }

    /** The values of an observed view; a value the view does not hold is left out. */
    public static Map<String, String> of(BaselineView view) {
        return SecurityDecisionPromptValues.viewLines(Objects.requireNonNull(view, "view"));
    }

    /** {@code 25 protected requests in the last 7 days; protectable share 0.40} of an observed view. */
    public static String workProfile(CanonicalSecurityContext.WorkProfile workProfile, BaselineView view) {
        return SecurityDecisionPromptValues.workProfile(workProfile, Objects.requireNonNull(view, "view"));
    }

    /** {@code window 7 days}, the Evidence line's window before its first and last day. */
    public static String evidenceWindow(BaselineView view) {
        return SecurityDecisionPromptValues.evidenceWindow(Objects.requireNonNull(view, "view"));
    }

    /** {@code observations 25 over 5 days}. */
    public static String evidenceObservations(BaselineView view) {
        return SecurityDecisionPromptValues.evidenceObservations(Objects.requireNonNull(view, "view"));
    }

    /** {@code collector ROLE_SCOPE_PROFILE}: the name the Evidence line gives a trust profile. */
    public static String collectorName(ContextTrustProfile trust) {
        return SecurityDecisionPromptValues.collectorName(Objects.requireNonNull(trust, "trust"));
    }
}
