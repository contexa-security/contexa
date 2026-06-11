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
package io.contexa.contexacore.autonomous.context.policy;

import org.springframework.util.StringUtils;

import java.util.List;

public final class PromptRelevantRequestPathPolicy {

    private static final List<String> NOISE_PATH_FRAGMENTS = List.of(
            "/admin/test/",
            "/test/",
            "/customlogin",
            "/admin/mfa/",
            "/login/mfa",
            "/api/test-action/status",
            "/api/sse/llm-analysis/",
            "/api/security-test/evidence/");

    private PromptRelevantRequestPathPolicy() {
    }

    public static boolean isPromptRelevantPath(String requestPath) {
        return isPromptRelevantText(requestPath);
    }

    public static boolean isPromptRelevantActionSummary(String actionSummary) {
        if (isGeneratedBehaviorSentence(actionSummary)) {
            return false;
        }
        return isPromptRelevantText(actionSummary);
    }

    private static boolean isGeneratedBehaviorSentence(String actionSummary) {
        if (!StringUtils.hasText(actionSummary)) {
            return false;
        }
        String normalized = actionSummary.trim().toLowerCase();
        return normalized.startsWith("user accessed ");
    }

    private static boolean isPromptRelevantText(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.trim().toLowerCase();
        for (String fragment : NOISE_PATH_FRAGMENTS) {
            if (normalized.contains(fragment)) {
                return false;
            }
        }
        return true;
    }
}
