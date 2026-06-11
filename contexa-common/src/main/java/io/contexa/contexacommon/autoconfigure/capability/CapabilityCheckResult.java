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
package io.contexa.contexacommon.autoconfigure.capability;

import java.util.List;

public record CapabilityCheckResult(
        ContexaCapability capability,
        CapabilityStatus status,
        boolean required,
        String reason,
        List<String> presentBeans,
        List<String> missingBeans,
        List<String> recommendations) {

    public CapabilityCheckResult {
        presentBeans = List.copyOf(presentBeans == null ? List.of() : presentBeans);
        missingBeans = List.copyOf(missingBeans == null ? List.of() : missingBeans);
        recommendations = List.copyOf(recommendations == null ? List.of() : recommendations);
    }

    public boolean shouldFail(CapabilityMode mode) {
        if (!required || mode == CapabilityMode.OFF || mode == CapabilityMode.WARN) {
            return false;
        }
        return status == CapabilityStatus.INACTIVE_UNEXPECTED || status == CapabilityStatus.FAILED;
    }
}
