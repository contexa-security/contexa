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
package io.contexa.contexaidentity.security.core.mfa.policy;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

@Getter
@Builder
public class CompletionDecision {
    private final boolean completed;
    private final boolean needsFactorSelection;
    private final int attemptCount;
    private final String errorMessage;
    private final List<String> missingRequiredStepIds;

    public static CompletionDecision completed() {
        return CompletionDecision.builder()
            .completed(true)
            .needsFactorSelection(false)
            .build();
    }

    public static CompletionDecision needsFactorSelection(int attemptCount) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(true)
            .attemptCount(attemptCount)
            .build();
    }

    public static CompletionDecision incomplete(List<String> missingSteps) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(true)
            .missingRequiredStepIds(missingSteps)
            .build();
    }

    public static CompletionDecision error(String message) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(false)
            .errorMessage(message)
            .build();
    }
}
