package io.contexa.contexacore.std.streaming;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import org.springframework.http.codec.ServerSentEvent;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Standard streaming service interface for Contexa platform.
 * Provides unified streaming API with support for both Strategy/Lab path
 * and direct Pipeline execution.
 *
 * <p>Usage examples:</p>
 * <pre>{@code
 * // Strategy/Lab path (AICoreOperations type)
 * streamingService.stream(request, aiNativeProcessor);
 *
 * // Direct Pipeline execution (PipelineOrchestrator type)
 * streamingService.stream(request, pipelineOrchestrator);
 * }</pre>
 */
public interface StandardStreamingService {

    /**
     * Streams response using Strategy/Lab path via AICoreOperations.
     * This path enables DiagnosisType-based routing and domain-specific processing.
     *
     * @param <C>         the context type
     * @param request     the AIRequest to process
     * @param aiProcessor the AICoreOperations processor (Strategy/Lab path)
     * @return SSE stream of responses
     */
    <C extends DomainContext> Flux<ServerSentEvent<String>> stream(
            AIRequest<C> request,
            AICoreOperations<C> aiProcessor
    );


    /**
     * Streams response directly via PipelineOrchestrator, bypassing Strategy/Lab.
     * Use this for simple LLM calls or custom prompt execution.
     *
     * @param request the AIRequest to process
     * @param pipelineOrchestrator the PipelineOrchestrator for direct execution
     * @param <C> the context type
     * @return SSE stream of responses
     */
    <C extends DomainContext> Flux<ServerSentEvent<String>> stream(
            AIRequest<C> request,
            PipelineOrchestrator pipelineOrchestrator
    );

    /**
     * Processes a single (non-streaming) response using Strategy/Lab path.
     *
     * @param request the AIRequest to process
     * @param aiProcessor the AICoreOperations processor
     * @param responseType the expected response type
     * @param <C> the context type
     * @param <R> the response type
     * @return Mono containing the response
     */
    <C extends DomainContext, R extends AIResponse> Mono<R> process(
            AIRequest<C> request,
            AICoreOperations<C> aiProcessor,
            Class<R> responseType
    );

    /**
     * Processes a single (non-streaming) response directly via PipelineOrchestrator.
     *
     * @param request the AIRequest to process
     * @param pipelineOrchestrator the PipelineOrchestrator for direct execution
     * @param responseType the expected response type
     * @param <C> the context type
     * @param <R> the response type
     * @return Mono containing the response
     */
    <C extends DomainContext, R extends AIResponse> Mono<R> process(
            AIRequest<C> request,
            PipelineOrchestrator pipelineOrchestrator,
            Class<R> responseType
    );

    /**
     * Creates an error SSE stream with the specified error details.
     *
     * @param errorCode the error code
     * @param message the error message
     * @return SSE stream containing the error
     */
    Flux<ServerSentEvent<String>> errorStream(String errorCode, String message);
}
