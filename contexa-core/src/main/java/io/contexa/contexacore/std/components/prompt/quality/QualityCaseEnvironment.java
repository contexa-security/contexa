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
package io.contexa.contexacore.std.components.prompt.quality;

import java.time.ZoneId;

/**
 * What a case fixes of the environment it is replayed in (plan 3.2), so that one case is not a different input under
 * another server setting: the time zone its times are drawn in and the version of the canonical context format its
 * input is written in.
 *
 * @param timeZone             the id of the time zone, such as {@code UTC}
 * @param contextFormatVersion the version of the canonical context format
 */
public record QualityCaseEnvironment(String timeZone, String contextFormatVersion) {

    /**
     * The canonical context format of the first cases, which is the one this build reads and writes: the one version
     * of the format the core declares. The replay of a sealed decision compares the format a case names with it
     * ({@code SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION} is this value). A change of the format that an earlier
     * case cannot be read under takes the next number, and the replay then reads the new one.
     */
    public static final String FIRST_CONTEXT_FORMAT = "1";

    public QualityCaseEnvironment {
        if (timeZone == null || timeZone.isBlank()) {
            throw new IllegalArgumentException("A labelled case fixes its time zone");
        }
        if (contextFormatVersion == null || contextFormatVersion.isBlank()) {
            throw new IllegalArgumentException("A labelled case names the context format its input is written in");
        }
        timeZone = ZoneId.of(timeZone.trim()).getId();
        contextFormatVersion = contextFormatVersion.trim();
    }
}
