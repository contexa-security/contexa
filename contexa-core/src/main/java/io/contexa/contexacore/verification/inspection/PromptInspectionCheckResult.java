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
 * What one check counted on a sealed prompt: the items that matched, the items that did not, the items it could not
 * check, and a finding for each item that did not count as matching.
 */
public record PromptInspectionCheckResult(
        String checkCode,
        int matched,
        int mismatched,
        int unverifiable,
        List<PromptInspectionFinding> findings,
        List<Integer> matchedLines) {

    public PromptInspectionCheckResult {
        Objects.requireNonNull(checkCode, "checkCode");
        findings = findings == null ? List.of() : List.copyOf(findings);
        matchedLines = matchedLines == null ? List.of() : List.copyOf(matchedLines);
    }

    /** A check result without the matched lines, as the result store keeps it. */
    public PromptInspectionCheckResult(String checkCode, int matched, int mismatched, int unverifiable,
                                       List<PromptInspectionFinding> findings) {
        this(checkCode, matched, mismatched, unverifiable, findings, List.of());
    }

    /** Every item the check looked at. */
    public int checked() {
        return matched + mismatched + unverifiable;
    }
}
