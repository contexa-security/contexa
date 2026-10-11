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
package io.contexa.contexacore.std.components.prompt.bundle;

import java.util.List;
import java.util.Map;

/**
 * The fixed inputs the golden render digest (element B3) is computed from: the resource, the SHA-256 of its
 * uncompressed content, the rendered cases, the cases that have no prompt input and the budget profiles rendered.
 */
public record PromptBundleGoldenInputs(
        String resource,
        String sha256,
        int caseCount,
        Map<String, String> excludedCases,
        List<String> renderProfiles) {

    public PromptBundleGoldenInputs {
        excludedCases = excludedCases == null ? Map.of() : Map.copyOf(excludedCases);
        renderProfiles = renderProfiles == null ? List.of() : List.copyOf(renderProfiles);
    }
}
