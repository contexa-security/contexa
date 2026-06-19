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
package io.contexa.contexacore.hcad.trigger.window;

import java.util.List;

public record HcadObservationWindowLease(
        boolean deepEvaluationOwner,
        String actorSessionKey,
        String windowId,
        int requestCount,
        List<String> resourceFamilies,
        List<String> samplePaths
) {
    public HcadObservationWindowLease {
        resourceFamilies = resourceFamilies == null ? List.of() : List.copyOf(resourceFamilies);
        samplePaths = samplePaths == null ? List.of() : List.copyOf(samplePaths);
    }

    public int duplicateSuppressedCount() {
        return Math.max(0, requestCount - 1);
    }
}
