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
package io.contexa.contexaiam.aiam.event;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import lombok.RequiredArgsConstructor;

import java.util.Map;

/**
 * Decorator for LlmAnalysisEventListener that publishes
 * Zero Trust SSE events for BLOCK/ESCALATE page real-time notifications,
 * while delegating to the existing implementation (e.g., LlmAnalysisEventListenerImpl)
 * to preserve security-test.html SSE functionality.
 *
 * Registered as @Primary via IamAiamZeroTrustSseAutoConfiguration.
 */
@RequiredArgsConstructor
public class ZeroTrustAnalysisEventListener implements LlmAnalysisEventListener {

    private final ZeroTrustSsePublisher ssePublisher;
    private final LlmAnalysisEventListener delegate;

    @Override
    public void onContextCollected(String userId, String requestPath) {
        if (delegate != null) {
            delegate.onContextCollected(userId, requestPath);
        }
    }

    @Override
    public void onContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
        if (delegate != null) {
            delegate.onContextCollected(userId, requestPath, metadata);
        }
    }

    @Override
    public void onLayer1Start(String userId, String requestPath) {
        if (delegate != null) {
            delegate.onLayer1Start(userId, requestPath);
        }
    }

    @Override
    public void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        if (delegate != null) {
            delegate.onLayer1Start(userId, requestPath, metadata);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
        }
    }

    @Override
    public void onLayer1Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER1", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer1Complete(userId, action, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onHcadAnalysis(String userId, Map<String, Object> hcadData) {
        if (delegate != null) {
            delegate.onHcadAnalysis(userId, hcadData);
        }
    }

    @Override
    public void onSessionContextLoaded(String userId, Map<String, Object> sessionData) {
        if (delegate != null) {
            delegate.onSessionContextLoaded(userId, sessionData);
        }
    }

    @Override
    public void onRagSearchComplete(String userId, int matchedCount, long ragSearchMs) {
        if (delegate != null) {
            delegate.onRagSearchComplete(userId, matchedCount, ragSearchMs);
        }
    }

    @Override
    public void onBehaviorAnalysisComplete(String userId, Map<String, Object> behaviorData) {
        if (delegate != null) {
            delegate.onBehaviorAnalysisComplete(userId, behaviorData);
        }
    }

    @Override
    public void onLlmExecutionStart(String userId, String modelName, long promptBuildMs) {
        if (delegate != null) {
            delegate.onLlmExecutionStart(userId, modelName, promptBuildMs);
        }
    }

    @Override
    public void onLlmExecutionComplete(String userId, long llmExecutionMs, long responseParseMs) {
        if (delegate != null) {
            delegate.onLlmExecutionComplete(userId, llmExecutionMs, responseParseMs);
        }
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason) {
        if (delegate != null) {
            delegate.onLayer2Start(userId, requestPath, reason);
        }
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        if (delegate != null) {
            delegate.onLayer2Start(userId, requestPath, reason, metadata);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, riskScore, confidence, reasoning, mitre, elapsedMs, metadata);
        }
    }

    @Override
    public void onLayer2Complete(String userId, String action,
                                  String reasoning, String mitre, Long elapsedMs) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.analysisProgress(
                userId, "LAYER2", action, reasoning, mitre);
        ssePublisher.publishAnalysisProgress(userId, event);

        if (delegate != null) {
            delegate.onLayer2Complete(userId, action, reasoning, mitre, elapsedMs);
        }
    }

    @Override
    public void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount, int totalAnalysisCount) {
        if (delegate != null) {
            delegate.onEscalateProtectionTriggered(userId, requestPath, escalateCount, totalAnalysisCount);
        }
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.decisionComplete(
                userId, action, layer, requestPath, null, null);
        ssePublisher.publishDecision(userId, event);

        if (delegate != null) {
            delegate.onDecisionApplied(userId, action, layer, requestPath);
        }
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.decisionComplete(
                userId, action, layer, requestPath, null, null);
        ssePublisher.publishDecision(userId, event);

        if (delegate != null) {
            delegate.onDecisionApplied(userId, action, layer, requestPath, metadata);
        }
    }

    @Override
    public void onError(String userId, String message) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.error(userId, message);
        ssePublisher.publishError(userId, event);

        if (delegate != null) {
            delegate.onError(userId, message);
        }
    }

    @Override
    public void onError(String userId, String message, Map<String, Object> metadata) {
        ZeroTrustSseEvent event = ZeroTrustSseEvent.error(userId, message);
        ssePublisher.publishError(userId, event);

        if (delegate != null) {
            delegate.onError(userId, message, metadata);
        }
    }
}