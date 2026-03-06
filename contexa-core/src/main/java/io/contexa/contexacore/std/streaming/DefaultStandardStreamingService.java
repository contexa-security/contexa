package io.contexa.contexacore.std.streaming;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.Protectable;
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
    @Protectable
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
        streamingContext.appendChunk(chunkStr);

        if (streamingContext.isFinalResponseStarted()) {
            return Flux.empty();
        }
        if (chunkStr.contains(StreamingProtocol.GENERATING_RESULT_MARKER)) {
            return Flux.just(createDataEvent(StreamingProtocol.GENERATING_RESULT_MARKER));
        }

        return streamingContext.getSentenceBuffer().processChunk(chunkStr)
                .map(this::createDataEvent);
    }

    private Mono<ServerSentEvent<String>> extractJsonIfNeeded(
            StreamingContext streamingContext) {

        return Mono.defer(() -> {
            String jsonPart = streamingContext.extractJsonPart();
            if (jsonPart != null && !streamingContext.isJsonSent()) {
                streamingContext.markJsonSent();
                return Mono.just(createDataEvent(jsonPart));
            }
            return Mono.empty();
        });
    }

    private Flux<ServerSentEvent<String>> flushRemainingBuffer(
            StreamingContext streamingContext) {

        if (streamingContext.isFinalResponseStarted()) {
            return Flux.empty();
        }
        return streamingContext.getSentenceBuffer().flush()
                .map(this::createDataEvent);
    }

    private Mono<ServerSentEvent<String>> createDoneEvent() {
        return Mono.just(ServerSentEvent.<String>builder()
                .data(DONE_MARKER)
                .build());
    }

    private ServerSentEvent<String> createDataEvent(String data) {
        String sanitizedData = data;
        if (data != null) {
            sanitizedData = data.replace("\r\n", " ").replace("\n", " ").replace("\r", " ");
        }
        return ServerSentEvent.<String>builder()
                .data(sanitizedData)
                .build();
    }

    private Flux<ServerSentEvent<String>> handleStreamError(Throwable error) {
        log.error("Streaming error occurred", error);

        String errorCode;
        String errorMessage;

        switch (error) {
            case AIOperationException aiOperationException -> {
                errorCode = "AI_OPERATION_ERROR";
                errorMessage = error.getMessage();
            }
            case TimeoutException timeoutException -> {
                errorCode = "TIMEOUT";
                errorMessage = "Request timed out";
            }
            case IllegalArgumentException illegalArgumentException -> {
                errorCode = "INVALID_REQUEST";
                errorMessage = error.getMessage();
            }
            case null, default -> {
                errorCode = "INTERNAL_ERROR";
                errorMessage = "An unexpected error occurred";
            }
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
