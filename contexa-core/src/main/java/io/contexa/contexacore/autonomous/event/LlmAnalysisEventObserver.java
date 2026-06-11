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
package io.contexa.contexacore.autonomous.event;

import java.util.Map;

public interface LlmAnalysisEventObserver {

    default void onContextCollected(String userId, String requestPath) {
    }
    default void onContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
        onContextCollected(userId, requestPath);
    }

    default void onLayer1Start(String userId, String requestPath) {
    }
    default void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        onLayer1Start(userId, requestPath);
    }

    default void onLayer1Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
    }
    default void onLayer1Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        onLayer1Complete(userId, action, reasoning, mitre, elapsedMs);
    }

    default void onLayer2Start(String userId, String requestPath, String reason) {
    }
    default void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        onLayer2Start(userId, requestPath, reason);
    }

    default void onLayer2Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
    }
    default void onLayer2Complete(
            String userId,
            String action,
            Double riskScore,
            Double confidence,
            String reasoning,
            String mitre,
            Long elapsedMs,
            Map<String, Object> metadata) {
        onLayer2Complete(userId, action, reasoning, mitre, elapsedMs);
    }

    default void onDecisionApplied(String userId, String action, String layer, String requestPath) {
    }
    default void onDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        onDecisionApplied(userId, action, layer, requestPath);
    }

    default void onError(String userId, String message) {
    }
    default void onError(String userId, String message, Map<String, Object> metadata) {
        onError(userId, message);
    }

    default void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
    }
    default void onEscalateProtectionTriggered(
            String userId,
            String requestPath,
            int escalateCount,
            int totalAnalysisCount,
            Map<String, Object> metadata) {
        onEscalateProtectionTriggered(userId, requestPath, escalateCount, totalAnalysisCount);
    }

    default void onHcadAnalysis(String userId, Map<String, Object> hcadData) {
    }

    default void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {
    }

    default void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
    }

    default void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
    }

    default void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
    }

    default void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
    }
}
