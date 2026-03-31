package io.contexa.sandbox.fullstack.prompt;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class SandboxStableDecisionCaptureStore {

    private static final ConcurrentMap<String, StableDecisionCapture> CAPTURES = new ConcurrentHashMap<>();

    private SandboxStableDecisionCaptureStore() {
    }

    static void capture(StableDecisionCapture capture) {
        if (capture == null || capture.requestId() == null || capture.requestId().isBlank()) {
            return;
        }
        CAPTURES.put(capture.requestId(), capture);
    }

    static Optional<StableDecisionCapture> find(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(CAPTURES.get(requestId));
    }

    static void clearAll() {
        CAPTURES.clear();
    }

    record StableDecisionCapture(
            String requestId,
            String boundaryMode,
            String modelId,
            String aiGenerationType,
            String targetResponseType,
            Boolean structuredOutputComplete,
            Object llmRawRequest,
            Object llmRawResponse,
            Object llmExecutionResult,
            Map<String, Object> pipelineMetadata) {
    }
}
