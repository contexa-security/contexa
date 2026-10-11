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
package io.contexa.contexacore.autonomous.learning.evidence;

import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;

public record CurrentLearningContextSnapshot(
        String accessHour,
        String dayOfWeek,
        String network,
        String browser,
        String operatingSystem,
        String pathFamily,
        String authenticationType,
        String actionFamily,
        String resourceFamily) {

    /** The request's device, one dimension: the browser on the operating system (W2-4). */
    public String device() {
        return SecuritySemanticNormalizer.device(browser, operatingSystem);
    }
}
