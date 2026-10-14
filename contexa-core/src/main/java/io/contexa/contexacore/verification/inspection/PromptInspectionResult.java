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
package io.contexa.contexacore.verification.inspection;

import java.util.List;
import java.util.Objects;

/**
 * The inspection of one sealed package: the versions it was inspected with, the verdict, what each check counted and
 * found, and why the package could not be inspected when it could not.
 */
public record PromptInspectionResult(
        String packageId,
        String inspectorVersion,
        String dictionaryVersion,
        String layoutVersion,
        PromptInspectionVerdict verdict,
        List<PromptInspectionCheckResult> checks,
        String errorReason) {

    public PromptInspectionResult {
        Objects.requireNonNull(verdict, "verdict");
        checks = checks == null ? List.of() : List.copyOf(checks);
    }

    public int matchedCount() {
        return checks.stream().mapToInt(PromptInspectionCheckResult::matched).sum();
    }

    public int mismatchCount() {
        return checks.stream().mapToInt(PromptInspectionCheckResult::mismatched).sum();
    }

    public int unverifiableCount() {
        return checks.stream().mapToInt(PromptInspectionCheckResult::unverifiable).sum();
    }

    public List<PromptInspectionFinding> findings() {
        return checks.stream().flatMap(check -> check.findings().stream()).toList();
    }
}
