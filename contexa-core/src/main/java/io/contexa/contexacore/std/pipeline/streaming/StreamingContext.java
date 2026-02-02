package io.contexa.contexacore.std.pipeline.streaming;

import io.contexa.contexacore.utils.SentenceBuffer;
import lombok.Getter;

/**
 * Complete streaming context with sentence buffering support.
 * Extends BaseStreamingContext and integrates SentenceBuffer for converting
 * LLM chunk output into complete sentences for streaming to clients.
 *
 * <p>This class is the primary entry point for custom streaming implementations.
 * It provides all functionality needed to handle LLM streaming responses,
 * including chunk accumulation, marker detection, and sentence-level buffering.</p>
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * StreamingProperties properties = ...; // injected via Spring
 * StreamingContext context = new StreamingContext(properties);
 *
 * return aiProcessor.processStream(request)
 *     .flatMap(chunk -> {
 *         context.appendChunk(chunk);
 *         if (context.isFinalResponseStarted()) {
 *             return Flux.empty();
 *         }
 *         return context.getSentenceBuffer().processChunk(chunk)
 *             .map(sentence -> ServerSentEvent.builder().data(sentence).build());
 *     });
 * }</pre>
 */
@Getter
public class StreamingContext extends BaseStreamingContext {

    private final SentenceBuffer sentenceBuffer;

    /**
     * Creates a new streaming context with the specified properties.
     *
     * @param properties the streaming configuration properties
     */
    public StreamingContext(StreamingProperties properties) {
        super(properties);
        this.sentenceBuffer = new SentenceBuffer();
    }

    /**
     * Creates a new streaming context with default properties.
     */
    public StreamingContext() {
        super();
        this.sentenceBuffer = new SentenceBuffer();
    }

}
