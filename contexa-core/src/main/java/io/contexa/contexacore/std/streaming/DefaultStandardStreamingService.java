package io.contexa.contexacore.std.streaming;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.streaming.StreamingContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.codec.ServerSentEvent;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Default implementation of StandardStreamingService.
 * Handles all streaming boilerplate including chunk processing,
 * sentence buffering, JSON extraction, and error handling.
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultStandardStreamingService implements StandardStreamingService {

    private static final String DONE_MARKER = "[DONE]";
    private static final String ERROR_PREFIX = "ERROR: ";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(5);

    private final StreamingProperties streamingProperties;
    private final ObjectMapper objectMapper;

    @Override
    public <C extends DomainContext> Flux<ServerSentEvent<String>> stream(
            AIRequest<C> request,
            AICoreOperations<C> aiProcessor) {
        return executeStrategyStream(request, aiProcessor)
                .timeout(DEFAULT_TIMEOUT)
                .onErrorResume(this::handleStreamError);
    }

    @Override
    public <C extends DomainContext> Flux<ServerSentEvent<String>> stream(
            AIRequest<C> request,
            PipelineOrchestrator pipelineOrchestrator) {
        return executeDirectStream(request, pipelineOrchestrator)
                .timeout(DEFAULT_TIMEOUT)
                .onErrorResume(this::handleStreamError);
    }

    @Override
    public <C extends DomainContext, R extends AIResponse> Mono<R> process(
            AIRequest<C> request,
            AICoreOperations<C> aiProcessor,
            Class<R> responseType) {
        return aiProcessor.process(request, responseType);
    }

    @Override
    public <C extends DomainContext, R extends AIResponse> Mono<R> process(
            AIRequest<C> request,
            PipelineOrchestrator pipelineOrchestrator,
            Class<R> responseType) {
        return pipelineOrchestrator.execute(request, responseType);
    }

    @Override
    public Flux<ServerSentEvent<String>> errorStream(String errorCode, String message) {
        return Flux.just(ServerSentEvent.<String>builder()
                .data(ERROR_PREFIX + buildErrorJson(errorCode, message))
                .build());
    }

    private <C extends DomainContext> Flux<ServerSentEvent<String>> executeStrategyStream(
            AIRequest<C> request,
            AICoreOperations<C> aiProcessor) {

        StreamingContext streamingContext = new StreamingContext(streamingProperties);

        return aiProcessor.processStream(request)
                .flatMap(chunk -> processChunk(chunk, streamingContext))
                .concatWith(extractJsonIfNeeded(streamingContext))
                .concatWith(flushRemainingBuffer(streamingContext))
                .concatWith(createDoneEvent());
    }

    private <C extends DomainContext> Flux<ServerSentEvent<String>> executeDirectStream(
            AIRequest<C> request,
            PipelineOrchestrator pipelineOrchestrator) {

        StreamingContext streamingContext = new StreamingContext(streamingProperties);

        return pipelineOrchestrator.executeStream(request)
                .flatMap(chunk -> processChunk(chunk, streamingContext))
                .concatWith(extractJsonIfNeeded(streamingContext))
                .concatWith(flushRemainingBuffer(streamingContext))
                .concatWith(createDoneEvent());
    }

    private Flux<ServerSentEvent<String>> processChunk(String chunk, StreamingContext streamingContext) {

        String chunkStr = chunk != null ? chunk : "";

//        log.debug("[SSE-CHUNK] Received chunk: length={}, preview={}",
//            chunkStr.length(),
//            chunkStr.length() > 100 ? chunkStr.substring(0, 100) + "..." : chunkStr);

        streamingContext.appendChunk(chunkStr);

        if (streamingContext.isFinalResponseStarted()) {
//            log.debug("[SSE-CHUNK] FINAL_RESPONSE detected, returning empty");
            return Flux.empty();
        }

        // Special markers bypass SentenceBuffer and are sent directly to client
        if (chunkStr.contains(StreamingProtocol.GENERATING_RESULT_MARKER)) {
            return Flux.just(createDataEvent(StreamingProtocol.GENERATING_RESULT_MARKER));
        }

        return streamingContext.getSentenceBuffer().processChunk(chunkStr)
//                .doOnNext(sentence -> log.debug("[SSE-SENTENCE] Sending sentence: {}",
//                    sentence.length() > 100 ? sentence.substring(0, 100) + "..." : sentence))
                .map(this::createDataEvent);
    }

    private Mono<ServerSentEvent<String>> extractJsonIfNeeded(
            StreamingContext streamingContext) {

        return Mono.defer(() -> {
            String jsonPart = streamingContext.extractJsonPart();
            if (jsonPart != null && !streamingContext.isJsonSent()) {
                log.debug("[SSE-JSON] Sending JSON response: {}", jsonPart);
                log.debug("[SSE-JSON] Sending JSON response: length={}", jsonPart.length());
                streamingContext.markJsonSent();
//                log.debug("[SSE-JSON] JSON content (first 500): {}",
//                    jsonPart.length() > 500 ? jsonPart.substring(0, 500) + "..." : jsonPart);
//                log.debug("[SSE-JSON] JSON content (last 500): {}",
//                    jsonPart.length() > 500 ? "..." + jsonPart.substring(jsonPart.length() - 500) : jsonPart);
                return Mono.just(createDataEvent(jsonPart));
            }
            return Mono.empty();
        });
    }

    private Flux<ServerSentEvent<String>> flushRemainingBuffer(
            StreamingContext streamingContext) {

        log.debug("[SSE-FLUSH] flushRemainingBuffer called: isFinalResponseStarted={}",
            streamingContext.isFinalResponseStarted());

        // Do not flush buffer after FINAL_RESPONSE - prevents JSON corruption
        // from leftover buffer data being appended after JSON response
        if (streamingContext.isFinalResponseStarted()) {
            log.debug("[SSE-FLUSH] Skipping flush - FINAL_RESPONSE already started");
            return Flux.empty();
        }

        return streamingContext.getSentenceBuffer().flush()
                .doOnNext(data -> log.debug("[SSE-FLUSH] Flushing data: {}",
                    data.length() > 100 ? data.substring(0, 100) + "..." : data))
                .map(this::createDataEvent);
    }

    private Mono<ServerSentEvent<String>> createDoneEvent() {
        return Mono.just(ServerSentEvent.<String>builder()
                .data(DONE_MARKER)
                .build());
    }

    private ServerSentEvent<String> createDataEvent(String data) {
        // SSE multiline bug fix: Remove newlines to prevent client parsing issues
        // Client splits by '\n' and only processes lines starting with 'data:'
        // JSON with newlines causes data loss (e.g., '],' between lines gets dropped)
        String sanitizedData = data;
        if (data != null && data.contains("\n")) {
            sanitizedData = data.replace("\n", "").replace("\r", "");
        }
        return ServerSentEvent.<String>builder()
                .data(sanitizedData)
                .build();
    }

    private Flux<ServerSentEvent<String>> handleStreamError(Throwable error) {
        log.error("Streaming error occurred", error);

        String errorCode;
        String errorMessage;

        if (error instanceof AIOperationException) {
            errorCode = "AI_OPERATION_ERROR";
            errorMessage = error.getMessage();
        } else if (error instanceof TimeoutException) {
            errorCode = "TIMEOUT";
            errorMessage = "Request timed out";
        } else if (error instanceof IllegalArgumentException) {
            errorCode = "INVALID_REQUEST";
            errorMessage = error.getMessage();
        } else {
            errorCode = "INTERNAL_ERROR";
            errorMessage = "An unexpected error occurred";
        }

        return errorStream(errorCode, errorMessage);
    }

    private String buildErrorJson(String errorCode, String errorMessage) {
        try {
            Map<String, Object> errorMap = Map.of(
                    "error", Map.of(
                            "code", errorCode != null ? errorCode : "UNKNOWN",
                            "message", errorMessage != null ? errorMessage : "Unknown error"
                    )
            );
            return objectMapper.writeValueAsString(errorMap);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize error JSON", e);
            return "{\"error\":{\"code\":\"SERIALIZATION_ERROR\",\"message\":\"Failed to serialize error\"}}";
        }
    }
}
